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