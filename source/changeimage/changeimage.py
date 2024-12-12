#!/usr/bin/env python

# Copyright 2020 The WebRoot, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Last modified: 2024.11.21 17:46:08

"""
Program acts as mutating webhook.
There are two webhooks:
1. Replaces Deployment, StatefulSet, DaemonSet, Pod definitiona while it is being created
   The replace is based on a set of regular expretions bound to namespace
2. Adds label to created, modified namespace according if it exists in the imagerules CRDs
   (explicitly or implicitly)
"""

from flask import Flask, request, jsonify
from prometheus_flask_exporter import PrometheusMetrics
import base64
import copy
import json
import jsonpatch
import logging
import re
import os
import sys
import threading
import time
import atexit
from kubernetes import client, config, watch
from datetime import datetime, timedelta, timezone

semNamespace = threading.Semaphore(1) # semaphore for namespaces dictionary
sempdDisable = threading.Semaphore(1) # semaphore for podDisable dictionary
semimageRules = threading.Semaphore(1) # semaphore for *ImageRules dictionary
app = Flask(__name__)

# Set Global variablesa
webhookVersion = "2.4, Last modified: 2024.11.21 17:46:08"
podName = os.getenv("POD_NAME")
webhookNamespace = os.getenv("WEBHOOK_NAMESPACE", "default")
logLevel = os.getenv("LOG_LEVEL", "INFO")
disableLabel = os.getenv("DISABLE_LABEL", "k8s.pg.io/changeimage")
webhookAnnotation = os.getenv("WEBHOOK_ANNOTATION", "k8s.pg.io/changeimage")
webhookWorkloadPath = os.getenv("WEBHOOK_WORKLOAD_PATH", "/workload")
webhookCrdPath = os.getenv("WEBHOOK_CRD_PATH", "/crd")
webhookLeaseName = "webhook-leader-lease"
webhookLeaseDurationSeconds = 15
webhookLeaseRenewIntervalSeconds = 5
implicitImageRules = []
explicitImageRules = []
defaultImageRules = []
podDisable = []
namespaces = {}
needNamespacesRelabel = True
# Setup Prometheus Metrics for Flask app
metrics = PrometheusMetrics(app, defaults_prefix="changeimage")

# Static information as metric
metrics.info("app_info", "Application info", version=webhookVersion)

# Set logging config
myID = f"{podName.split('-')[-1]}/{os.getpid()}"

logging.basicConfig(format=f"%(asctime)s %(levelname)s {myID} %(funcName)s %(message)s")
log = logging.getLogger(__name__)
#log.disabled = True
log.setLevel(logLevel)

### Kubernetes APIs
v1 = None
crd_api = None
coordination_api = None
################################################################################
def onExit():
    """
    Cleanup on exit
    """
    if acquireLease(webhookLeaseName):
        log.info(f"releasing Lease {webhookLeaseName} at exit")
        releaseLease(webhookLeaseName)
################################################################################
def InitConfig():
    """Function to init kubernetes config and client """
    global v1
    global crd_api
    global coordination_api

    try:
        config.load_incluster_config()
    except:
        log.info("Could not get kube config")
        sys.exit(1)

    v1 = client.CoreV1Api()
    crd_api = client.CustomObjectsApi()
    coordination_api = client.CoordinationV1Api()
################################################################################
################################################################################
# Leases
################################################################################
def createOrGetLease(LeaseName):
    """
    Function to create or get lease
    """
    try:
        lease = coordination_api.read_namespaced_lease(LeaseName,webhookNamespace)
    except client.exceptions.ApiException as e:
        if e.status == 404:  # Lease does not exist
            lease = client.V1Lease(
                metadata=client.V1ObjectMeta(name=LeaseName, namespace=webhookNamespace),
                spec=client.V1LeaseSpec(
                    holder_identity=myID,
                    lease_duration_seconds=webhookLeaseDurationSeconds,
                    acquire_time=datetime.now(timezone.utc),
                    renew_time=datetime.now(timezone.utc),
                ),
            )
            try:
                lease = coordination_api.create_namespaced_lease(webhookNamespace, lease)
            except client.exceptions.ApiException as e:
                if e.status == 409:  # Conflict - some any process created lease in meantime
                    log.info(f"{LeaseName}: Seems an other proces updeated lease... sleeping 1 sec and trying again")
                    time.sleep(1)
                    return(createOrGetLease(LeaseName))
    return lease
################################################################################
def acquireLease(LeaseName):
    """
    Function acquires lease - needed to lock the namespaces modification (label)
    """
    lease = createOrGetLease(LeaseName)
    log.debug(f"red lease - id: {lease.spec.holder_identity}")
    if lease.spec.holder_identity == myID:
        return renewLease(LeaseName)

    # Check lease expiration
    if (
        lease.spec.renew_time and (
            lease.spec.holder_identity == None
            or lease.spec.renew_time + timedelta(seconds=webhookLeaseDurationSeconds) < datetime.now(timezone.utc)
            )
        ):
        log.debug(f"changeing: {lease.spec.holder_identity} {lease.spec.renew_time}")
        lease.spec.holder_identity = myID
        lease.spec.acquire_time = datetime.now(timezone.utc)
        lease.spec.renew_time = datetime.now(timezone.utc)
        try:
            coordination_api.replace_namespaced_lease(LeaseName, webhookNamespace, lease)
        except client.exceptions.ApiException as e:
            if e.status == 409:  # Conflict - some any process created lease in meantime
                log.info(f"{LeaseName}: Seems an other proces updeated lease... giving up")
                return False
        log.debug("Gathered lease")
        return True
    return False

################################################################################
def SetLease(LeaseName,id):
    """
    Function to set Lease with given id, after acquirind lease with myID
    """
    lease = coordination_api.read_namespaced_lease(LeaseName, webhookNamespace)
    if lease.spec.holder_identity == myID or lease.spec.holder_identity == f"{myID}-relabel":
        lease.spec.holder_identity = id
        lease.spec.renew_time = datetime.now(timezone.utc)
        try:
            coordination_api.replace_namespaced_lease(LeaseName, webhookNamespace, lease)
        except client.exceptions.ApiException as e:
            if e.status == 409:  # Conflict - some any process created lease in meantime
                log.info(f"{LeaseName}: Seems an other proces updeated lease...")
            else:
                log.info(f"{LeaseName}: exception {e}")
            return False

        return True
    return False

################################################################################
def NamespaceLabelsLoop():
    """
    After thread acquires lease - its job is to check and relabel all namespaces - once if enough
    """
    global needNamespacesRelabel

    while needNamespacesRelabel:
        NamespacesLabels()
        time.sleep(10)
    log.info(f"relabeled namespcases - finishing thread")
################################################################################
def renewLeaseLoop(LeaseName):
    """
    Function in a loop renews lease, if already acquired 
    """
    global webhookLeaseRenewIntervalSeconds
    while True:
        ret = acquireLease(LeaseName)
        if ret:
            log.debug(f"{myID}  - acquired lease")
        else:
            log.debug(f"{myID}  -  not acquired lease")
        time.sleep(webhookLeaseRenewIntervalSeconds)
################################################################################
def renewLease(LeaseName):
    """
    Function to renew acquired lease - new timestamps
    This function has not been used in this code
    Keeped fot future
    """
    lease = coordination_api.read_namespaced_lease(LeaseName, webhookNamespace)
    if lease.spec.holder_identity == myID or lease.spec.holder_identity == f"{myID}-relabel":
        lease.spec.renew_time = datetime.now(timezone.utc)
        try:
            coordination_api.replace_namespaced_lease(LeaseName, webhookNamespace, lease)
        except client.exceptions.ApiException as e:
            if e.status == 409:  # Conflict - some any process created lease in meantime
                log.info(f"{LeaseName}: Seems an other thread updeated lease... sleeping 100 ms and continue renewLease")
                time.sleep(.1)
                return renewLease(LeaseName)
            else:
                log.info(f"{LeaseName}: exception {e}")
            return(False)
        log.debug(f"lease renewed: {lease.spec.renew_time}")
        return True
    log.info("I've lost lease")
    return False  # Lost the lease

################################################################################
def releaseLease(LeaseName):
    """
    Function to release lease, after job done
    """
    lease = coordination_api.read_namespaced_lease(LeaseName, webhookNamespace)
    if lease.spec.holder_identity == myID or lease.spec.holder_identity == f"{myID}-relabel" :
        lease.spec.holder_identity = None
        coordination_api.replace_namespaced_lease(LeaseName, webhookNamespace, lease)
################################################################################
################################################################################
def getCRD(plural,d):
    """
    Function reads all CRD type of "plural" and writes them to dict "d"
    """
    del d[:]

    # Define the group, version, and plural name of the custom resource
    group = "pg.io"
    version = "v1"

    try:
    # List all instances of the CRD in the specified namespace
#        api_response = api_instance.list_cluster_custom_object(
        api_response = crd_api.list_cluster_custom_object(
            group=group,
            version=version,
            plural=plural
            )
        d.extend(api_response.get("items", []))
    except client.exceptions.ApiException as e:
        print(f"Exception when calling CustomObjectsApi->list_namespaced_custom_object: {e}")
        sys.exit(1)

################################################################################
def addRuleToNamespaces(nss,rules,name):
    """
    Function converts rules from imagerules crd to namespaces dictionary
    """
    for ns in nss:
        # add only if namespace does not exists in the namespaces dict
        # the namespace can exist if it was added by explicitImageRules
        # and now the function was called to add implicit or default..ImageRules
        if ns in namespaces:
            log.info(f"namespace {ns} already in namespaces list")
            return(None)
        # We need to ommit own namespace from labaling, it is because:
        # setting own namespace to label (i.e. by DefaultImageRules)
        # in case uninstalling this deployment and then installing it again
        # the webhook will not start, because apiserver will try to connect
        # MW to mutate starting pod, but the webhook is not running yet, so mutation will fail
        # and the MW will not start
        # so own namespace (webhookNamespace) must not be labeled
        # The same is if own namespace is labaled, and you scale down to 0 the deployment
        # and the scale up. (BTW scaling down to 0 the MW is bad idea, while it breaks mutationg for all
        # labeled namespaces)
        if ns == webhookNamespace:
            log.warning(f"Namespace {webhookNamespace} can not be labaled - omitting")
            continue

        log.debug(f"adding {ns} {rules} to namespaces")
        namespaces[ns] = {}
        namespaces[ns]["rules"] = []
        namespaces[ns]["name"] = name
        for line in rules:
        # Skip commented lines
            if line[0] == "#":
                continue
        # Trim trailing comments
            if "#" in line:
                line = re.sub(r"(^.*[^#])(#.*$)", r"\1", line)
        # Trim whitespace
            line = re.sub(r" ", "", line.rstrip())
        # Skip empty lines
            if not line:
                continue
        # Check for new style separator ("::") and verify the map splits correctly
            if "::" in line and len(line.split("::")) == 3:
                (pattern, replace, cont) = line.split("::")
                log.debug(f"line: {line}")
                log.debug(f"pattern: {pattern}, replace: {replace}, cont: {cont}")
                namespaces[ns]["rules"].append({
                    "pattern": pattern,
                    "replace": replace,
                    "cont" : cont
                    })
            else:
            # Check if map key contains a ":port" and that the new style separator ("::") is not used
                if line.count(":") > 1 and "::" not in line:
                    log.warning(
                        f'Invalid map is specified. A port in the map key or value requires using "::" as the separator. Skipping map for line: {line}'
                        )
            # Warn for any other invalid map syntax
                else:
                    log.warning(f"Invalid map is specified. Incorrect syntax for map definition. Skipping map for line: {line}")
                    continue
        # Store processed line key/value pair in map

################################################################################
def prepareNamespaces():
    """
    Function crete dictionary "namespaces" based on red CRD imagerules
    The "namespaces" dictionary contains: 
    key - the namespace name
    naspaces[key] = {'name': rule-name, 'rules': [{'patterns':patterns, 'replace':replace, 'cont':cont} regex rules used to change image ] }
    """

    # expicitImageRules
    namespaces.clear()
    for item in explicitImageRules:
        addRuleToNamespaces(item["spec"]["namespaces"],item["spec"]["rules"],item["metadata"]["name"])

    allNS = v1.list_namespace()
    # implicitImageRules
    for item in implicitImageRules:
        for ns in allNS.items:
            if ns.metadata.name not in item["spec"]["excludedNamespaces"]:
                log.debug(f"implicit adding ns: {ns.metadata.name} to namespaces, rules: {item['spec']['rules']} ")
                addRuleToNamespaces([ns.metadata.name] ,item["spec"]["rules"],item["metadata"]["name"])

    # defaulImageRule
    for item in defaultImageRules:
        for ns in allNS.items:
            log.debug(f"default adding ns: {ns.metadata.name} to namespaces, rules: {item['spec']['rules']} ")
            addRuleToNamespaces([ns.metadata.name] ,item["spec"]["rules"],item["metadata"]["name"])

    return(None)

################################################################################
def patchNamespace(name,body):
    """
    Function patches namespace
    Adding or removing label
    """
#    v1 = client.CoreV1Api()
    try:
        v1.patch_namespace(name=name, body=body)
    except client.exceptions.ApiException as e:
        log.error(f"failed to patch namespaces {name}: {e}")
        return(False)

    return(True)
################################################################################
def checkUnsetLabel(ns):
    """
    Function checks and eventually unset (if set) label to unmark namespace for webhook
    """
    labels = ns.metadata.labels or {}
    if disableLabel not in labels or labels[disableLabel] == "disabled":
        log.debug(f"Checked namespace {ns.metadata.name} - {disableLabel} already unset - OK")
        return(False)
    body = {
        "metadata": {
            "labels": {
                disableLabel: None
            }
        }
    }
    log.info(f"Patching namespace {ns.metadata.name}: {body}")
    return(patchNamespace(ns.metadata.name,body))

################################################################################
def checkSetLabel(ns):
    """
    Function checks and eventually set (if not set) label to mark namespace for webhook
    """
    labels = ns.metadata.labels or {}
    if disableLabel in labels and labels[disableLabel] == "enabled":
        log.debug(f"Checked namespace {ns.metadata.name} - {disableLabel} already set - OK")
        return(False)

    body = {
        "metadata": {
            "labels": {
                disableLabel: "enabled"
            }
        }
    }
    log.info(f"Patching namespace {ns.metadata.name}: {body}")
    return(patchNamespace(ns.metadata.name,body))

################################################################################
def LabelNamespace(ns):
    """
    Function to label namespace according to the existence of the namespace
    in namespaces dictionary
    """
    log.debug(f"checking {ns.metadata.name}")
    if ns.metadata.name in namespaces:
        log.debug(f"set label {ns.metadata.name}")
        checkSetLabel(ns)
    else:
        log.debug(f"unset label {ns.metadata.name}")
        checkUnsetLabel(ns)
    return(None)
################################################################################
def NamespacesLabels():
    """
    Function checks and modifies (if needed) namespaces labels, according to
    namespaces dictionry (based on *ImageRules CRD)
    function is called when webhook starts and then any changes to CRDs are made
    """

    global needNamespacesRelabel
    # Acquire Lease - only one process can do relabeling
    if acquireLease(webhookLeaseName):
        log.info(f"Acquired lease, labeling namespaces")

        # Set Lease holder to another value, than myID - prevent watching threads
        # to relablel namespace while this relables fonction is in progress
        # set the lease owner to nonexisting process
        id=f"{myID}-relabel"
        if not SetLease(webhookLeaseName,id):
            return(None)
        allNS = v1.list_namespace()
        for ns in allNS.items:
            log.debug(f"current namespaces dict: {namespaces}")
            LabelNamespace(ns)

        SetLease(webhookLeaseName,myID)
        needNamespacesRelabel = False
        # Release Lease - the owner was set to nonexisting process

    else:
        log.debug(f"Could not acquire lease, skiping labeling namespaces")
    return(None)
################################################################################
def readCRDs():
    """
    Function rereads CRD poddisable and *Imagerules
    to appropriate dictionaries and the call function
    to convert *ImageRules to dictionary "namespaces"
    This function is called after any change in the CRDs objects
    """
    global podDisable
    global implicitImageRules
    global explicitImageRules
    global defaultImageRules

    # Set semaphores while CRDs are being red
    # To prevent an other thread uses dictionary while reading is not complete
    sempdDisable.acquire()
    getCRD("poddisable",podDisable)
    sempdDisable.release()
    log.debug(f"podDisble: {podDisable}")

    semimageRules.acquire()
    getCRD("implicitimagerules",implicitImageRules)
    getCRD("explicitimagerules",explicitImageRules)
    getCRD("defaultimagerules",defaultImageRules)
    semimageRules.release()
    log.debug(f"implicitImageRules: {implicitImageRules}")
    log.debug(f"explicitImageRules: {explicitImageRules}")
    log.debug(f"defaultImageRules: {defaultImageRules}")

    semNamespace.acquire()
    prepareNamespaces()
    semNamespace.release()

    NamespacesLabels()

################################################################################
################################################################################

def addAnnotation(object,oldImage,newImage,containerName):
    """
    Function adds annotation to workload in case images change
    """
    metaData = object["request"]["object"]["metadata"]

    if not "annotations" in  metaData:
        metaData["annotations"] = {}
    if not webhookAnnotation in metaData["annotations"]:
        metaData["annotations"][webhookAnnotation] = "changed images:"

    ann = f"\ncontainer {containerName},from: {oldImage}, to: {newImage}"
    metaData["annotations"][webhookAnnotation] = metaData["annotations"][webhookAnnotation] + ann
    log.debug(f"Added annotation: {ann}")

################################################################################
def watchNamespaces():
    """
    Function watches events of modification namespaces
    In case addidng or modifying namespace - it checks namespace lables
    """
    
    w = watch.Watch()
    while True:
        try:
            for event in w.stream(v1.list_namespace):
                if event['type'] in ['ADDED', 'MODIFIED']:
                    if acquireLease(webhookLeaseName):
                        log.debug(f"Event: {event['type']} - namespace {event['object'].metadata.name} trying to relabel namespaces")
                        LabelNamespace(event['object'])
                    else:
                        # Namespace labeling is beeing perofmed by another process
                        # or namespaces are beeing relabeled
                        # because of change configuratin and the event is the result 
                        # of the namespaces relabeling
                        log.debug(f"Event: {event['type']} - namespace {event['object'].metadata.name} can not get lease to relabel namespaces")
        except client.rest.ApiException as e:
            if e.status == 410:
                log.info("Resource version expired (namespace), restarting watch...")
                continue
            else:
                raise
################################################################################
def watchCRD(plural):
    """
    Function watches evens of modification given crd.
    In case any change to CRD, calls reread all crds and relabel namespaces
    """

    group = "pg.io"
    version = "v1"

    w = watch.Watch()
    while True:
        try:
            for event in w.stream(crd_api.list_cluster_custom_object, group, version, plural):
                if event['type'] in ['ADDED', 'MODIFIED', 'DELETED']:
                    log.info(f"Event: {event['type']} - {plural} {event['object']['metadata']['name']} reread config")
                    # reread CRDs
                    # I have to consider if all CRDs read is needed
                    # or just plural type
                    # but it runs fast, so....
                    readCRDs()  # Reread all objects
        except client.rest.ApiException as e:
            if e.status == 410:
                log.info(f"Resource version expired {plural}, restarting watch...")
                continue
            else:
                raise
################################################################################
def startWatchingThread(*args, **kwargs):
    thr = threading.Thread(*args, **kwargs)
    thr.daemon = True
    thr.start()
################################################################################
def setup_function():
    """
    Function to setup working space, called at the beginining of the program 
    - inits kubernetes config
    - reads CRDs
    - starts threads watching poddsisable and imagerules crds
    """
    log.debug("inside setup_function")
    atexit.register(onExit)
    InitConfig()
    readCRDs()

    startWatchingThread(target=watchCRD, args=("poddisable",))
    startWatchingThread(target=watchCRD, args=("implicitimagerules",))
    startWatchingThread(target=watchCRD, args=("explicitimagerules",))
    startWatchingThread(target=watchCRD, args=("defaultimagerules",))
    startWatchingThread(target=watchNamespaces)
    startWatchingThread(target=renewLeaseLoop, args=(webhookLeaseName,))
    startWatchingThread(target=NamespaceLabelsLoop)


################################################################################
def allowDoNotModify(requestInfo):
    """
    Function returns admissionReview response - "allowd, nothing modified"
    """
    admissionResponse = {
        "allowed": True,
        "uid": requestInfo["request"]["uid"],
        }

    admissionReview = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": admissionResponse,
        }
    log.debug(f"admissionReview: {json.dumps(admissionReview)}")
    return(jsonify(admissionReview))

################################################################################
def compareNamespace(orLabels,ns):
    """
    Function check if given namespace (ns) exists in the poddisable definition
    """
    if not "namespaces" in orLabels:
        # There is no namespaces in the poddisable crd
        # So it applies to all namespaces
        return(True)
    
    for n in orLabels["namespaces"]:
        if ns == n:
            # namespace ns exists in the namespaces 
            return(True)
    return(False)
################################################################################
def checkDisabled(workloadMetadata):
    """
    Function to check if workload contains label which disables changeimage
    Worklad labels are compared against poddisable CRDs
    If it finds matching rule, returns string with the info
    Otherwise returns None
    """
    if ("labels" in workloadMetadata):
        log.debug(f"searching {disableLabel} = \"disabled\" in {workloadMetadata['labels']}")

        # At first checks the "main" label, defined by disableLabel variable
        if (disableLabel in workloadMetadata["labels"]
        and workloadMetadata["labels"][disableLabel] == "disabled"
        ):
            return(f"has label {disableLabel} = \"disabled\" skipping change image")
    else:
        log.debug(f"no labels in metadata")
        return(None)

    # at this point we have labels and do not have 'disableLabel'
    log.debug(f"object labels {workloadMetadata['labels']} ....")
    for labeldisable in podDisable:
        for orLabels in labeldisable["spec"]:
            log.debug(f"comparing with {labeldisable['metadata']['name']}: {orLabels} ")
            if(compareNamespace(orLabels,workloadMetadata["namespace"])):
                Match = True
                log.debug(f"We are going through {orLabels['andLabels']}")
                for item in orLabels["andLabels"]:
                    for label, value in item.items():
                        if (
                            not label in workloadMetadata["labels"]
                            or value != workloadMetadata["labels"][label]
                            ):
                            Match = False
                            break
                    if not Match:
                        break
                if Match:
                    return(f'podDisable rule {labeldisable["metadata"]["name"]} matched ')

        
    return(None)
################################################################################
def getWorkloadName(workloadMetadata,modifiedSpec):
    """
    Function to get workload name, based on metadata
    It checks 'name' then 'generateName' and lastely request 'uid'
    """
    if "name" in workloadMetadata:
        return(workloadMetadata["name"])

    if "generateName" in workloadMetadata:
        return(workloadMetadata["generateName"])

    return(modifiedSpec["request"]["uid"])

################################################################################
def LogInfoDebug(test,msg):
    """
    Function to log msg, in info level if test is true, otherwise in debug level
    """
    if test:
        log.info(msg)
    else:
        log.debug(msg)
################################################################################
def changeImage(containerSpec,namespace,test=False):
    """
    Function to perform changeImage for a container spec
    It is the main logic
    """

    if not namespace in namespaces:
        # in fact we should never reach this point, because only namespaces
        # in the "namespaces" dictionary have the label
        # witch is in the mutatingwebhookcofiguration as the namespaceSelector
        # and only for this namespaces the webhook should be called
        # OR .. it is called from the test function
        LogInfoDebug(test,f"namespace {namespace} not found in {namespaces}")
        return(False)

    image = containerSpec["image"]
    newImage = image
    orgImage = image

    LogInfoDebug(test,f"parsing image: {image}")

    changed = False

    LogInfoDebug(test,f"checking img: {image} against rules {namespaces[namespace]} ")

    # waith for semaphor and lock it to prevent 
    # changing of namespace dictionary (due to adding/modifying/removing CRDs)
    semNamespace.acquire()

    for r in namespaces[namespace]["rules"]:
        LogInfoDebug(test,f"compare pattern {r['pattern']} with image: {image}")
        # I need to check the match - re.sub is not sufficient, because
        # we can have rule, which does not change the image but its job is to stop
        # parsing rules
        match = re.search(r["pattern"],image)
        if match:
            LogInfoDebug(test,f"image: {image} mathes pattern: {r['pattern']}")
            newImage = re.sub(r["pattern"],r["replace"],image)
            if image != newImage:
                changed = True
                image = newImage
                LogInfoDebug(test,f"changed image to: {newImage}")
            else:
                LogInfoDebug(test,f"Image has not been changed - stop rule???")
            if r["cont"] and r["cont"].lower() == "stop":
                LogInfoDebug(test,f"stop parsing - cont = stop")
                break

    semNamespace.release()
    LogInfoDebug(test,f"Finished parsing image - final result: {newImage}")
    if changed:
        LogInfoDebug(test,f"changeImage: Changed image {orgImage} with {newImage}")
        containerSpec["image"] = newImage

    return changed

################################################################################
def rejectValidatingRequest(uid,message):
        review = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "code": 403,
                    "message": message
                }
            }
        }
        return(jsonify(review))
################################################################################
def validateExplicitImageRules(requestInfo):
    """
    function to validate ExplicitImageRules CDR
    We can not have explicitly defined different rules for the same namespace
    """
    reqObj = requestInfo.get('request', {})
    crd = reqObj.get('object')
    crdNamespaces = crd.get("spec", {}).get("namespaces", [])
    existsNamespaces = {}
    existsNS = False

    log.debug(f"namespaces from crd: {crdNamespaces}")

    for ns in crdNamespaces:
        for item in explicitImageRules:
            if ns in item["spec"]["namespaces"]:
                # Check if it is applied patch - the same crd name
                if item["metadata"]["name"] != crd.get("metadata", {}).get("name"):
                    existsNS = True
                    # I do not exit immediately, because I want to gather all
                    # already existed namespaces in imagerules
                    existsNamespaces[ns]=item["metadata"]["name"]
    
    if existsNS:
        message = "Following namespaces already exist in explicitimagerules:"
        for key, value in existsNamespaces.items():
            message = message + f"\nnamespace: {key},eir: {value}, check with \"kubectl get eir {value} -o yaml\""
        
        return(rejectValidatingRequest(requestInfo["request"]["uid"],message))
    else:
        return(allowDoNotModify(requestInfo))

################################################################################
def validateImplicitImageRules(requestInfo):
    """
    function to validate ImplicitImageRules CDR
    We can not have more than one ImplicitImageRule (with excludedNamespaces)
    """

    # if we have already defined one implicitImageRules
    if implicitImageRules:
        # Check if it is applied patch - the same crd name
        newCrdName = requestInfo.get('request', {}).get('object').get("metadata", {}).get("name")
        currentCrdName = implicitImageRules[0]["metadata"]["name"]
        if newCrdName != currentCrdName:
            message = f'Implicit Image Rule already exists: {implicitImageRules[0]["metadata"]["name"]}'
            return(rejectValidatingRequest(requestInfo["request"]["uid"],message))

    return(allowDoNotModify(requestInfo))
################################################################################
def validateDefaultImageRules(requestInfo):
    """
    function to validate DefaultImageRules CDR
    We can not have more than one DefaultImageRule (with excludedNamespaces)
    """

    # if we have already defined one defaultImageRules
    if defaultImageRules:
        # Check if it is applied patch - the same crd name
        newCrdName = requestInfo.get('request', {}).get('object').get("metadata", {}).get("name")
        currentCrdName = defaultImageRules[0]["metadata"]["name"]
        if newCrdName != currentCrdName:
            message = f"Default Image Rule already exists: {defaultImageRules[0]['metadata']['name']}"
            return(rejectValidatingRequest(requestInfo["request"]["uid"],message))

    return(allowDoNotModify(requestInfo))
################################################################################
def mutateWorkload(modifiedSpec,podSpec):
    workloadMetadata = modifiedSpec["request"]["object"]["metadata"]
    workloadType = modifiedSpec["request"]["kind"]["kind"]
    workload = getWorkloadName(workloadMetadata,modifiedSpec)
    namespace = modifiedSpec["request"]["namespace"]
    needsPatch = False

    for containerSpec in podSpec["containers"]:

        log.debug(f"Processing container: {namespace}/{workloadType}/{workload}/{containerSpec['name']}")
        orgImage = containerSpec["image"]
        nP = changeImage(containerSpec,namespace)
        if nP:
            needsPatch = True
            newImage = containerSpec["image"]
            log.info(f"{namespace}/{workloadType}/{workload} container {containerSpec['name']}, changed image from: {orgImage} to {newImage}")
            addAnnotation(modifiedSpec,orgImage,newImage,containerSpec["name"])

    # checking initContainers in pod
    if "initContainers" in podSpec:

        for initContainerSpec in podSpec["initContainers"]:

            log.debug(f"Processing init-container: {namespace}/{workloadType}/{workload}/{containerSpec['name']}")
            orgImage = initContainerSpec["image"]
            nP = changeImage(initContainerSpec,namespace)
            if nP:
                log.info(f"{namespace}/{workloadType}/{workload} init container {initContainerSpec['name']}, changed image from: {orgImage} to {newImage}")
                needsPatch = True
                newImage = containerSpec["image"]
                addAnnotation(modifiedSpec,orgImage,newImage,initContainerSpec["name"])

    return needsPatch

################################################################################

############################# MAIN #############################################

log.info(f"webhook started: version {webhookVersion}")
log.info(f"logLevel set to {logLevel}")
setup_function()


@app.route(webhookWorkloadPath, methods=["POST"])
def mutate():
    """
    Function to run main logic to handle changeimage mutation
    """

    requestInfo = request.json
    log.debug(f"request: {json.dumps(requestInfo)}")
    modifiedSpec = copy.deepcopy(requestInfo)
    workloadMetadata = modifiedSpec["request"]["object"]["metadata"]
    workloadType = modifiedSpec["request"]["kind"]["kind"]
    workload = getWorkloadName(workloadMetadata,modifiedSpec)

    # wait for sempdDisable and lock it to avoid poddisable dictionary modification
    # during checking the workload
    sempdDisable.acquire()
    disableMessage = checkDisabled(workloadMetadata)
    sempdDisable.release()

    namespace = modifiedSpec["request"]["namespace"]

    # Skip patching if workloadMetadatadisable label is found and set to "disable"
    # Change workflow/json path based on K8s object type
    if disableMessage:
        log.info(f"{workloadType} {workload} in namespace {namespace}: {disableMessage}")
        return(allowDoNotModify(requestInfo))

    # flag, whether there was at least one change, so that a patch has to be returned
    needsPatch = False

    log.debug(json.dumps(request.json))


    if workloadType == "Pod":
        # checking containers in pod
        podSpec = modifiedSpec["request"]["object"]["spec"]
        needsPatch = mutateWorkload(modifiedSpec,podSpec) or needsPatch

    else:

        # checking containers in other workload types than pod
        # Deployment, DeamonSet, StatefulSet
        podSpec = modifiedSpec["request"]["object"]["spec"]["template"]["spec"]
        needsPatch = mutateWorkload(modifiedSpec,podSpec) or needsPatch

    if not needsPatch:
        log.debug("Doesn't need patch")
        return(allowDoNotModify(requestInfo))

    log.debug("Needs patch")
    log.debug("Diffing original request to modified request and generating JSONPatch")

    patch = jsonpatch.JsonPatch.from_diff(
        requestInfo["request"]["object"],
        modifiedSpec["request"]["object"]
        )

    log.debug(f"JSON Patch: {patch}")

    admissionResponse = {
        "allowed": True,
        "uid": requestInfo["request"]["uid"],
        "patch": base64.b64encode(str(patch).encode()).decode(),
        "patchType": "JSONPatch",
    }
    
    admissionReview = {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": admissionResponse,
        }

    log.debug("Sending Response to K8s API Server - patching workload")
    log.debug(f"Admission Review: {json.dumps(admissionReview)}")

    return(jsonify(admissionReview))


################################################################################
################################################################################
################################################################################
# Flask routes

@app.route("/healthz", methods=["GET"])
def healthz():

    """Function to return health info for app"""

    health_response = {
        "pod_name": podName,
        "date_time": str(datetime.now()),
        "health": "ok",
    }

    # Return JSON formatted response object
    return(jsonify(health_response))

################################################################################
@app.route(webhookCrdPath, methods=["POST"])
def validate():
    """
    Function to validate CRDs change (ADD,MODIFY,REMOVE)
    """
    requestInfo = request.get_json()
    
    log.debug(f"validation request: {requestInfo}")
    kind = requestInfo.get('request', {}).get("kind").get("kind")
    log.debug(f"validating {kind}")

    # Validation function depends on CRD kind
    if kind == "ExplicitImageRules":
        return(validateExplicitImageRules(requestInfo))
    if kind == "ImplicitImageRules":
        return(validateImplicitImageRules(requestInfo))
    if kind == "DefaultImageRules":
        return(validateDefaultImageRules(requestInfo))

    # We got another kind, than the validation webhook is ready
    # There is something wrong with ValidatinWebhookConfiguration
    log.error(f"Not defined kind: {kind} - passing on")
    return(allowDoNotModify(requestInfo))


################################################################################
@app.route("/test", methods=["POST"])
def testFunction():
    """
    Function to test the changeimage without applying config
    Example of the shell script:

    curl -k -X POST https://${WEBHOOKSERVICEIP}:${WEBHOOKSERVICEPORT}/test \
     -H "Content-Type: application/json" \
     -d "{\"namespace\": \"$IMAGENAMESPACE\", \"image\": \"$IMAGE\"}"

    """
    requestInfo = request.json
    log.debug(f"request: {json.dumps(requestInfo)}")
    if not "namespace" in requestInfo:
        return(jsonify("{'oputput': None, 'reason': 'Missing namespace in request}"))
    if not "image" in requestInfo:
        return(jsonify("{'oputput': None, 'reason': 'Missing image in request}"))


    image = requestInfo["image"]
    ns = requestInfo["namespace"]
    log.info(f"testing namespace: {ns}, image: {image}")
    if (changeImage(requestInfo,ns,test=True)):
        log.info(f"test result, namespace: {ns}, orgimage: {image}, newimage {requestInfo['image']}")
        message=f"changed {image} for namespace {ns}"
        answer = f"{{'output': {requestInfo['image']}, 'reason': {message}, 'controller': {myID}}}"
    else:
        log.info(f"test result, namespace: {ns}, image {image} not changed")
        message=f"not changed {image} for namespace {ns}"
        answer = f"{{'output': {image}, 'reason': {message}, 'controller': {myID}}}"
    return(jsonify(answer))
