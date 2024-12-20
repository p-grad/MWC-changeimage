# **ChangeImage**
Version 1.0  
URL: [https://github.com/p-grad/MWC-changeimage](https://github.com/p-grad/MWC-changeimage)  

## Mutating Admission Controller for Kubernetes

The ChangeImage [webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) allows the kubernetes to automatiacaly change the image deffinition during Pod, Deployment, StatefullSet, DaemonSet creation or modification.  The change is based on a regularExpression [rulesets](doc/rulesets/README.md). 

This is usefull in an dark site or airgapped configuration, where we want to change the image deffinition on fly, without modifying the deployment manifests. It helps as well to decrease the connection bandwith, changing the image registry to local image proxy.

This project based on:
[GitHub - phenixblue/imageswap-webhook: Image Swap Mutating Admission Webhook for Kubernetes](https://github.com/phenixblue/imageswap-webhook)

## Getting started

### Dependencies

- kubernetes

- helm

### Installing

```bash
git clone https://github.com/p-grad/MWC-changeimage.git
cd MWC-changeimage/changeimage
```

Modify the values.yaml file with you favorit text editor,  if needed.

Then implement the chart.

> helm install &lt;name&gt; . -n &lt;namespace&gt; --create-namespace

For example:

```bash
helm install chgimg . -n changeimage-system --create-namespace
```

### How it Works

When installing the solution, the Mutating Webhook (MW) and Validating Webhook (VW) will be registered in the Mutating Webhook Configuration (MWC) and Validating Webhook Configuration (VWC).

#### Mutating Webhook (MW)

The MW monitors newly created or modified workloads (e.g., Pods, Deployments, StatefulSets, and DaemonSets) and modifies image definitions within them. This is achieved based on configurations defined by custom resources (CRDs). These configurations link namespaces to specific image rulesets using regular expressions. The following CRDs are implemented:

- PodDisable (pd)
  A set of labels that, if present on a workload, prevent the workload from being processed by the image rules (described below).

- ExplicitImageRules (eir)
  Enables explicit binding of specific namespaces to defined rulesets.
  Ensures precise control over which namespaces are affected by particular image rules.

- ImplicitImageRules (iir)
  Assigns rulesets to all namespaces except those listed in the excludeNamespaces field or those defined by an eir.
  Provides a broad, default assignment mechanism for image rules.

- DefaultImageRules (dir)
  Assigns rules globally to all namespaces, except for those governed by eir or iir definitions.
  Acts as the fallback for namespaces without explicit or implicit rules.

##### Rule Evaluation Order

Image rules are assigned to namespaces in the following order:

- eir (ExplicitImageRules)

- iir (ImplicitImageRules)

- dir (DefaultImageRules)

This ensures a structured and predictable configuration hierarchy.

##### Key Constraints

Only one (or none) iir and one (or none) dir can exist in the configuration.
Multiple eir definitions are allowed, but a single namespace cannot appear in more than one eir definition.

##### Validating Webhook (VW)

The VW enforces the above key constraints during CRD creation or updates, ensuring compliance with the defined configurations.

### Testing  
If you want to test a new ruleset, the easiest way is to assign the ruleset to a nonexistent namespace using ExplicitImageRules.
For example:
```yaml
apiVersion: pg.io/v1
kind: ExplicitImageRules
metadata:
  name: test-eir
  annotations:
    comment: |-
      Test ruleset, aapplied to not existent namespace for test
spec:
  rules:
    - '^(my.harbor.local/.+)::\1::stop' # step1
    - '^([^/]+)$::my.harbor.local/docker.io/\1::stop' # step 2
    - '^([^\./]+/.+)$::my.harbor.local/docker.io/\1::stop' # step 3
    - '^(.+)$::my.harbor.local/\1::cont' # step 4
    - '^([^/]+)/([^:]+):[0-9]+/(.+)::\1/\2/\3::stop' # step 5 
  namespaces:
    - nonexistent-namespace
```
Then, you can test it with the following commands:  
```bash
   
IP=w.x.y.z	# IP address of the webhook service
PORT=443	# Port of the webhook service
IMAGE=test.harbor.com/nginx:v5	# Image the changing you want to test

curl -k -X POST https://${IP}:${PORT}/test \
     -H "Content-Type: application/json" \
     -d "{\"namespace\": \"nonexistent-namespace\", \"image\": \"$IMAGE\"}"
```

  
Here is an example:  
```bash
IP=10.98.250.238
PORT=443
IMAGE=nginx
curl -k -X POST https://${IP}:${PORT}/test      -H "Content-Type: application/json"      -d "{\"namespace\": \"nonexistent-namespace\", \"image\": \"$IMAGE\"}"
```
Expected response:  
```bash
{
  'output': my.harbor.local/docker.io/nginx,
  'reason': changed nginx for namespace nonexistent-namespace,
  'controller': zw54f/3
}
```
  
So, the controller zw54f (the controller pod name ends with zw54f) changed the image from nginx to my.harbor.local/docker.io/nginx.  

Additionally, you can check the controller logs. You will see something like this:  

```bash
kubectl logs chgimg-changeimage-59878b8948-zw54f
```
Example output:  
```log
...
2024-12-19 00:20:39,662 INFO zw54f/3 testFunction testing namespace: nonexistent-namespace, image: nginx
2024-12-19 00:20:39,663 INFO zw54f/3 LogInfoDebug parsing image: nginx
2024-12-19 00:20:39,663 INFO zw54f/3 LogInfoDebug checking img: nginx against rules {'rules': [{'pattern': '^(my.harbor.local/.+)', 'replace': '\\1', 'cont': 'stop'}, {'pattern': '^([^/]+)$', 'replace': 'my.harbor.local/docker.io/\\1', 'cont': 'stop'}, {'pattern': '^([^\\./]+/.+)$', 'replace': 'my.harbor.local/docker.io/\\1', 'cont': 'stop'}, {'pattern': '^(.+)$', 'replace': 'my.harbor.local/\\1', 'cont': 'cont'}, {'pattern': '^([^/]+)/([^:]+):[0-9]+/(.+)', 'replace': '\\1/\\2/\\3', 'cont': 'stop'}], 'name': 'test-eit'} 
2024-12-19 00:20:39,663 INFO zw54f/3 LogInfoDebug compare pattern ^(my.harbor.local/.+) with image: nginx
2024-12-19 00:20:39,663 INFO zw54f/3 LogInfoDebug compare pattern ^([^/]+)$ with image: nginx
2024-12-19 00:20:39,664 INFO zw54f/3 LogInfoDebug image: nginx matches pattern: ^([^/]+)$
2024-12-19 00:20:39,664 INFO zw54f/3 LogInfoDebug changed image to: my.harbor.local/docker.io/nginx
2024-12-19 00:20:39,664 INFO zw54f/3 LogInfoDebug stop parsing - cont = stop
2024-12-19 00:20:39,664 INFO zw54f/3 LogInfoDebug Finished parsing image - final result: my.harbor.local/docker.io/nginx
2024-12-19 00:20:39,664 INFO zw54f/3 LogInfoDebug changeImage: Changed image nginx with my.harbor.local/docker.io/nginx
2024-12-19 00:20:39,664 INFO zw54f/3 testFunction test result, namespace: nonexistent-namespace, orgimage: nginx, newimage my.harbor.local/docker.io/nginx
```
