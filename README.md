## GCP loadbalancer controller
[![build](https://github.com/GoogleCloudPlatform/gcp-lb-controller-rs/actions/workflows/build.yml/badge.svg)](https://github.com/GoogleCloudPlatform/gcp-lb-controller-rs/actions/workflows/build.yml)

This controller is for Kubernetes environments and provisions GCP loadbalancer infrastructure for services of type `LoadBalancer`.

### Currently Supported load balancers:

1. [External passthrough network load balancer](https://cloud.google.com/load-balancing/docs/network/setting-up-network-backend-service).

### Configuration:

| Annotation                         | Description                                                                                                                                                                                                                                                     |
|------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `gcp-lb-controller/hc-port`        | The port used to create health check. If not provided, first port in the <br/>service spec will be used.                                                                                                                                                        |
| `gcp-lb-controller/regional-migs`  | Comma separated regional managed instance groups. <br/>These should be in the same region as the cluster resources. If not provided zonal unmanaged instance groups will be created for all nodes in the cluster.                                               |
| `gcp-lb-controller/zonal-migs`     | Map of zonal managed instance groups, for example <br/>`"{\"us-central1-a\":\"instance-group-1\"}"`. These should be in the same region as the cluster resources. If not provided zonal unmanaged instance groups will be created for all nodes in the cluster. |
| `gcp-lb-controller/static-ip-name` | Static ip address resource name for the load balancer, this needs to be in the <br/>same region as the cluster.                                                                                                                                                 |

### Command line arguments

1. `network`: The network name of the instance, this is required.
2. `shared-vpc-project-id`: Shared VPC project id. The project id of the instance will be used if not provided.

### Build and deploy

1. Use the [`Dockerfile`](Dockerfile) to build the image and deploy using the manifests provided in [`k8s`](k8s).
2. Add the label `gcp-lb-controller=reconcile` to the services to enable provisioning the load balancer using the controller.
3. Debug logs can be enabled by setting the environment variable `RUST_LOG=debug`.

### Security model

- **Untrusted annotations:** All `Service` annotations and labels are treated as untrusted input because any user with permission to create or patch a `Service` in a namespace can set them. Every annotation value is validated against its expected syntax before use, and malformed values fail reconciliation rather than being ignored.
- **Ownership marker:** Every GCP resource created by the controller is tagged with `description: "gcp-lb-controller/service: <namespace>/<name>"`. Before updating, referencing, or deleting any controller-managed resource named by the controller's state annotations (`gcp-lb-controller/health-check`, `gcp-lb-controller/firewall-rule`, `gcp-lb-controller/backend-svc`, `gcp-lb-controller/forwarding-rule`, `gcp-lb-controller/instance-groups`), the controller fetches the resource from the Compute Engine API and verifies that its `description` matches the `Service` (or, for shared node instance groups, carries a controller ownership marker). The controller also refuses to use an existing unmanaged instance group named `lb-ig-<zone>` that does not carry its ownership marker; rename or remove that group to recover.
- **Do not edit resource descriptions:** Do not manually edit or clear the `description` field on GCP resources managed by this controller, and do not copy `gcp-lb-controller/*` state annotations (`health-check`, `firewall-rule`, `backend-svc`, `forwarding-rule`, `instance-groups`) onto another `Service`.
- **Recovering from an ownership error:** If reconciliation or cleanup fails with an ownership verification error, inspect the `Service` annotations and the target GCP resource. If the `Service` has a stale or copied state annotation pointing to another resource, update the annotation to the resource owned by `<namespace>/<name>` or remove the state annotation so the controller provisions a dedicated resource. If an operator modified the GCP resource's `description` by mistake, restore `gcp-lb-controller/service: <namespace>/<name>` on the GCP resource.

## Tools:

1. [Rust](https://www.rust-lang.org/learn/get-started)
2. kubectl

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for details.

## License

Apache 2.0. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This project is not an official Google project. It is not supported by
Google and Google specifically disclaims all warranties as to its quality,
merchantability, or fitness for a particular purpose.