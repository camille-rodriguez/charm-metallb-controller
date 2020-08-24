#!/usr/bin/env python3
# Copyright 2020 Camille Rodriguez
# See LICENSE file for licensing details.

from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os
import logging

from ops.charm import CharmBase
from ops.main import main
from ops.framework import StoredState
from ops.model import (
    ActiveStatus,
    MaintenanceStatus,
)

import utils

logger = logging.getLogger(__name__)


class MetallbCharm(CharmBase):
    _stored = StoredState()

    NAMESPACE = os.environ["JUJU_MODEL_NAME"]

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.start, self.on_start)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        self._stored.set_default(things=[])

    def _on_config_changed(self, _):
        current = self.model.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)

    def on_start(self, event):
        if not self.framework.model.unit.is_leader():
            return

        logging.info('Setting the pod spec')
        self.framework.model.unit.status = MaintenanceStatus("Configuring pod")
        # advertised_port = 7472 #charm_config['advertised-port']

        self.framework.model.pod.set_spec(
            {
                'version': 3,
                'serviceAccount': {
                    'roles' :  [{
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
                  ],
                },
                'containers': [{
                    'name': 'controller',
                    'image': 'metallb/controller:v0.9.3',
                    'imagePullPolicy': 'Always',
                    'ports': [{
                        'containerPort': 7472,
                        'protocol': 'TCP',
                        'name': 'monitoring'
                    }],
                    # 'cpu': 100,
                    # 'memory': 100,
                    # 'resources': {
                    #     'limits': {
                    #         'cpu': '100m',
                    #         'memory': '100Mi',
                    #     }
                    # },
                    'kubernetes': {
                        'securityContext': {
                            'privileged': False,
                            'runAsNonRoot': True,
                            'runAsUser': 65534,
                            'readOnlyRootFilesystem': True,
                            },
                        # 'capabilities': {
                        #     'drop': ['all']
                        # }
                    },
                }],
                'service': {
                    'annotations': {
                        'prometheus.io/port': '7472',
                        'prometheus.io/scrape': 'true'
                    }
                }
            },
        )

        logging.info('launching create_pod_spec_with_k8s_api')
        self.create_pod_spec_with_k8s_api()
        logging.info('Launching create_namespaced_role_with_api')
        self.create_namespaced_role_with_api()
        logging.info('Launching bind_role_with_api')
        self.bind_role_with_api()
        self.framework.model.unit.status = ActiveStatus("Ready")


    def create_pod_spec_with_k8s_api(self):
        # Using the API because of LP:1886694

        self._load_kube_config()

        metadata = client.V1ObjectMeta(
            namespace = self.NAMESPACE,
            name = 'controller',
            labels = {'app':'metallb'}
        )
        policy_spec = client.PolicyV1beta1PodSecurityPolicySpec(
            allow_privilege_escalation = False,
            default_allow_privilege_escalation = False,
            fs_group = client.PolicyV1beta1FSGroupStrategyOptions(
                ranges = [client.PolicyV1beta1IDRange(max=65535, min=1)], 
                rule = 'MustRunAs'
            ),
            host_ipc = False,
            host_network = False,
            host_pid = False,
            privileged = False,
            read_only_root_filesystem = True,
            required_drop_capabilities = ['ALL'],
            run_as_user = client.PolicyV1beta1RunAsUserStrategyOptions(
                ranges = [client.PolicyV1beta1IDRange(max=65535, min=1)], 
                rule = 'MustRunAs'
            ),
            se_linux = client.PolicyV1beta1SELinuxStrategyOptions(
                rule = 'RunAsAny',
            ),
            supplemental_groups = client.PolicyV1beta1SupplementalGroupsStrategyOptions(
                ranges = [client.PolicyV1beta1IDRange(max=65535, min=1)], 
                rule = 'MustRunAs'
            ),
            volumes = ['configMap', 'secret', 'emptyDir'],
        )

        body = client.PolicyV1beta1PodSecurityPolicy(metadata=metadata, spec=policy_spec)

        with client.ApiClient() as api_client:
            api_instance = client.PolicyV1beta1Api(api_client)
            try:
                api_instance.create_pod_security_policy(body, pretty=True)
            except ApiException:
                logging.exception("Exception when calling PolicyV1beta1Api->create_pod_security_policy.")

    def create_namespaced_role_with_api(self):
        # Using API because of bug https://github.com/canonical/operator/issues/390
        self._load_kube_config()

        with client.ApiClient() as api_client:
            api_instance = client.RbacAuthorizationV1Api(api_client)
            body = client.V1Role(
                metadata = client.V1ObjectMeta(
                    name = 'config-watcher',
                    namespace = self.NAMESPACE,
                    labels = {'app': 'metallb'}
                ),
                rules = [client.V1PolicyRule(
                    api_groups = [''],
                    resources = ['configmaps'],
                    verbs = ['get', 'list', 'watch'],
                )]
            )
            try:
                api_instance.create_namespaced_role(self.NAMESPACE, body, pretty=True)
            except ApiException:
                logging.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role.")

    def bind_role_with_api(self):
        # Using API because of bug https://github.com/canonical/operator/issues/390
        self._load_kube_config()

        with client.ApiClient() as api_client:
            api_instance = client.RbacAuthorizationV1Api(api_client)
            body = client.V1RoleBinding(
                metadata = client.V1ObjectMeta(
                    name = 'config-watcher',
                    namespace = self.NAMESPACE,
                    labels = {'app': 'metallb'}
                ),
                role_ref = client.V1RoleRef(
                    api_group = 'rbac.authorization.k8s.io',
                    kind = 'Role',
                    name = 'config-watcher',
                ),
                subjects = [
                    client.V1Subject(
                        kind = 'ServiceAccount',
                        name = 'metallb-controller'
                    ),
                ]
            )
            try:
                api_instance.create_namespaced_role_binding(self.NAMESPACE, body, pretty=True)
            except ApiException:
                logging.exception("Exception when calling RbacAuthorizationV1Api->create_namespaced_role_binding.")    
                

    def _load_kube_config(self):
        # TODO: Remove this workaround when bug LP:1892255 is fixed
        from pathlib import Path
        os.environ.update(
            dict(
                e.split("=")
                for e in Path("/proc/1/environ").read_text().split("\x00")
                if "KUBERNETES_SERVICE" in e
            )
        )
        # end workaround
        config.load_incluster_config()

if __name__ == "__main__":
    main(MetallbCharm)
