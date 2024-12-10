# **ChangeImage**
Version 1.0  

## Mutating Admission Controller for Kubernetes

The ChangeImage [webhook](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#admission-webhooks) allows the kubernetes to automatiacaly change the image deffinition during Pod, Deployment, StatefullSet, DaemonSet creation or modification.  The change is based on a regularExpression [rulesets](doc/rulesets/README.md). 

This is usefull in an dark site or airgapped configuration, where we want to change the image deffinition on fly, without modifying the deployment manifests. It helps as well to decrease the connection bandwith, changing the image registry to local image proxy.

This project based on:
[GitHub - phenixblue/imageswap-webhook: Image Swap Mutating Admission Webhook for Kubernetes](https://github.com/phenixblue/imageswap-webhook)

### 

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
