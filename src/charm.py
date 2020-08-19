#!/usr/bin/env python3
# Copyright 2020 Camille Rodriguez
# See LICENSE file for licensing details.

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

    def __init__(self, *args):
        super().__init__(*args)
        self.framework.observe(self.on.start, self.on_start)
        self.framework.observe(self.on.config_changed, self._on_config_changed)
        # self.framework.observe(self.on.fortune_action, self._on_fortune_action)
        self._stored.set_default(things=[])

    def _on_config_changed(self, _):
        current = self.model.config["thing"]
        if current not in self._stored.things:
            logger.debug("found a new thing: %r", current)
            self._stored.things.append(current)

    def on_start(self, event):
        if not self.framework.model.unit.is_leader():
            return

        # juju_pod_spec = utils.build_juju_pod_spec(
        #     app_name = self.framework.model.app.name,
        #     charm_config = self.framework.model.config,
        #     image_meta = ''
        # )
        logging.info('Setting the pod spec')
        
        advertised_port = 7472 #charm_config['advertised-port']
        app_name = 'metallb'

        # from kubernetes import client, config
        # from kubernetes.client.rest import ApiException

        # # config.load_kube_config(config_file='/home/crodriguez/.kube/config')
        # # policy_client = client.PolicyV1beta1Api()

        # pretty = 'pretty_example' # str | If 'true', then the output is pretty printed. (optional)
        # dry_run = 'dry_run_example' # str | When present, indicates that modifications should not be persisted. An invalid or unrecognized dryRun directive will result in an error response and no further processing of the request. Valid values are: - All: all dry run stages will be processed (optional)
        # field_manager = 'field_manager_example' # str | fieldManager is a name associated with the actor or entity that is making these changes. The value must be less than or 128 characters long, and only contain printable characters, as defined by https://golang.org/pkg/unicode/#IsPrint. (optional)
        # try:
        #     api_response = policy_client.create_pod_security_policy(body, pretty=pretty, dry_run=dry_run, field_manager=field_manager)
        #     pprint(api_response)
        # except ApiException as e:
        #     print("Exception when calling ExtensionsV1beta1Api->create_pod_security_policy: %s\n" % e)
        self.framework.model.pod.set_spec(
            {
                'version': 3,
                'serviceAccount': {
                  'roles' :  [{
                    # 'metadata': {
                    #   'labels': {
                    #        'app': app_name,
                    #    },
                    # 'name': 'controller',
                    # 'namespace': app_name,
                    # },
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
                  }],
                },
                'containers': [{
                    'name': 'metallb',
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
                    'kubernetes': {
                        'readinessProbe': {
                            'httpGet': {
                                'path': '/api/health',
                                'port': advertised_port
                            },
                            'initialDelaySeconds': 10,
                            'timeoutSeconds': 30
                        }
                    }   
                }]
            },
        )
        self.framework.model.unit.status = MaintenanceStatus("Configuring pod")

    import os
    logging.info('where am I... ' + os.envget)
    from kubernetes import client, config
    config.load_incluster_config()
    policy_client = client.PolicyV1beta1Api()
    v1 = client.CoreV1Api()
    v1.list_namespace()
    print(v1.list_namespace())




if __name__ == "__main__":
    main(MetallbCharm)
