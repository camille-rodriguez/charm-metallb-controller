import logging

from ops.model import (
    ActiveStatus,
    MaintenanceStatus,
)


log = logging.getLogger(__name__)


def build_juju_pod_spec(app_name,
                        charm_config,
                        image_meta,):
    advertised_port = 7472 #charm_config['advertised-port']

    spec = {
        {
            'version': 3,
            'serviceAccount': {
                'metadata': {
                    'labels': {
                        'app': app_name,
                    },
                'name': 'controller',
                'namespace': app_name,
                },
                'global': True,
                'rules': [
                    {
                        'apiGroups': [''],
                        'resources': ['services'],
                        'verbs': ['get', 'list', 'watch', 'update'],
                    },
                    {
                        'apiGroups': [''],
                        'resources': ['services/status'],
                        'verbs': ['update'],
                    },
                    {
                        'apiGroups': [''],
                        'resources': ['events'],
                        'verbs': ['create', 'patch'],
                    },
                    {
                        'apiGroups': ['policy'],
                        'resourceNames': ['controller'],
                        'resources': ['podsecuritypolicies'],
                        'verbs': ['use'],
                    },
                ],
            },
            'containers': [{
                'name': app_name,
                'image': 'metallb/controller:v0.9.3',
                # 'imageDetails': {
                #     'imagePath': image_meta.image_path,
                #     'username': image_meta.repo_username,
                #     'password': image_meta.repo_password
                # },
                'ports': [{
                    'containerPort': advertised_port,
                    'protocol': 'TCP'
                }],
                'readinessProbe': {
                    'httpGet': {
                        'path': '/api/health',
                        'port': advertised_port
                    },
                    'initialDelaySeconds': 10,
                    'timeoutSeconds': 30
                }
            }]
        },
        {
            'kubernetesResources': {
                'customResources': {
                    'ControllerPodPolicy': [
                        {
                            'apiVersion': 'policy/v1beta1',
                            'kind': 'PodSecurityPolicy',
                            'metadata': {
                                'labels': {'app': 'metallb'},
                                'name': 'controller',
                                'namespace': 'metallb',
                            },
                            'spec': 
                                {
                                    'allowPrivilegeEscalation': 'false',
                                    'allowedCapabilities': [],
                                    'allowedHostPaths': [],
                                    'defaultAddCapabilities': [],
                                    'defaultAllowPrivilegeEscalation': 'false',
                                    'fsGroup': {
                                        'ranges': ['max: 65535 min: 1'],
                                        'rule': 'MustRunAs',
                                    },
                                    'hostIPC': 'false',
                                    'hostNetwork': 'false',
                                    'hostPID': 'false',
                                    'privileged': 'false',
                                    'readOnlyRootFilesystem': 'true',
                                    'requiredDropCapabilities': ['ALL'],
                                    'runAsUser': {
                                        'ranges': ['max: 65535 min: 1'],
                                        'rule': 'MustRunAs',
                                    },
                                    'seLinux': {
                                        'rule': 'RunAsAny',
                                    },
                                    'supplementalGroups': {
                                        'ranges': {
                                        'ranges': ['max: 65535 min: 1'],
                                        'rule': 'MustRunAs',
                                        },
                                    'volumes': [ 'configMap', 'secret', 'emptyDir'],
                                    },
                                },
                        },
                    ],
                },
            },
        },
    }
    return spec


def build_juju_unit_status(pod_status):
    if pod_status.is_unknown:
        log.debug("k8s pod status is unknown")
        unit_status = MaintenanceStatus("Waiting for pod to appear")
    elif not pod_status.is_running:
        log.debug("k8s pod status is running")
        unit_status = MaintenanceStatus("Pod is starting")
    elif pod_status.is_running and not pod_status.is_ready:
        log.debug("k8s pod status is running but not ready")
        unit_status = MaintenanceStatus("Pod is getting ready")
    elif pod_status.is_running and pod_status.is_ready:
        log.debug("k8s pod status is running and ready")
        unit_status = ActiveStatus()

    return unit_status