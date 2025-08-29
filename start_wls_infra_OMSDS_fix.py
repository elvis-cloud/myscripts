#!/u01/app/oracle/product/fmw_12.2.1.4/oracle_common/common/bin/wlst.sh

"""
Create/Destroys servers in weblogic domain

References:
    Python 2.2.1 Documentation
    https://docs.python.org/release/2.2.1/

    WLST Command and Variable Reference
    https://docs.oracle.com/cd/E13222_01/wls/docs90/config_scripting/reference.html

    The WebLogic Server MBean Reference
    https://docs.oracle.com/cd/E13222_01/wls/docs90/wlsmbeanref/core/index.html
"""

import sys
import time
import os

from java.io import FileInputStream, FileOutputStream
from java.util import Properties
from weblogic.management.runtime import ServerStates
from weblogic.security.internal.encryption import ClearOrEncryptedService
from weblogic.security.internal.SerializedSystemIni import getEncryptionService
from javax.management import ObjectName
import jarray


class Logging:
    """Implements a basic logging interface"""

    def __init__(self):
        pass

    def _log(self, level, msg):
        print(level + ": " + msg)

    def info(self, msg):
        self._log("INFO", msg)

    def warning(self, msg):
        self._log("WARNING", msg)

    def error(self, msg):
        self._log("ERROR", msg)

    def fatal(self, msg):
        self._log("FATAL", msg)
        sys.exit(1)


class ArgumentParser:
    """A minimal implementation of argparse.ArgumentParser for Jython 2.2.1"""

    def __init__(self):
        self._namespace = Namespace()
        self._args = {}
        self._padding = 20
        self.add_argument("--help", help="show this help message and exit")

    def add_argument(self, arg, choices=None, default=None, required=False, help=""):
        self._args[arg] = {
            "name": self._argument_name(arg),
            "choices": choices or [],
            "required": required,
            "val": default,
            "help": help,
        }
        padding = len(arg)
        if choices:
            padding += len(str(choices)) + 4
        self._padding = max(self._padding, padding)

    def parse_args(self):
        self._parse_args()
        self._validate_args()
        for arg in self._args.values():
            setattr(self._namespace, arg["name"], arg["val"])
        return self._namespace

    def _parse_args(self):
        if len(sys.argv) == 1:
            return

        for i in range(1, len(sys.argv), 2):
            arg = sys.argv[i]
            if arg not in self._args:
                self.print_help()

            if arg == "--help":
                self.print_help()

            if i + 1 >= len(sys.argv):
                self.print_help()

            val = sys.argv[i + 1]
            self._args[arg]["val"] = val

    def _validate_args(self):
        for arg in self._args.values():
            val = arg["val"]
            choices = arg["choices"]
            required = arg["required"]

            if required and val is None:
                self.print_help()

            if val and choices and val not in choices:
                self.print_help()

    def _argument_name(self, arg):
        if arg[:2] != "--":
            raise NameError("argument name must start with --")
        if len(arg) <= 3:
            raise NameError("argument name cannot be empty")
        return arg[2:].replace("-", "_")

    def print_help(self):
        prog = os.path.basename(sys.argv[0])
        print("Usage: " + prog + " [OPTIONS]")
        print("")
        print("Options:")
        for k, v in self._args.items():
            s = []
            arg = k
            choices = v["choices"] or ""
            name = v["name"]
            help = v["help"]

            if choices:
                s.append(" ".join((arg, str(choices))).ljust(self._padding))
            elif arg == "--help":
                s.append(arg.ljust(self._padding))
            else:
                s.append(" ".join((arg, name.upper())).ljust(self._padding))
            if help:
                s.append(help)
            print(" ".join(s))
        sys.exit(1)


class Namespace:
    """A minimal implementation of argparse.Namespace for Jython 2.2.1"""


class PyProperties:
    """A wrapper for java.util.Properties with a pythonic interface
    https://docs.python.org/release/2.2.1/ref/sequence-types.html
    https://docs.oracle.com/javase/8/docs/api/java/util/Properties.html
    """

    def __init__(self, file="", comment=""):
        self.file = file
        self._properties = Properties()
        self._comment = comment
        if file:
            self.load(file)

    def load(self, file):
        self.file = file
        stream = FileInputStream(self.file)
        self._properties.load(stream)
        stream.close()

    def reload(self):
        self._properties.clear()
        self.load(self.file)

    def save(self):
        stream = FileOutputStream(self.file)
        self._properties.store(stream, self._comment)
        stream.close()

    def pop(self, key):
        val = self[key]
        del self[key]
        return val

    def __len__(self):
        return self._properties.size()

    def __getitem__(self, key):
        return self._properties.get(key)

    def __setitem__(self, key, item):
        self._properties.put(key, item)

    def __delitem__(self, key):
        self._properties.remove(key)

    def __contains__(self, key):
        return self._properties.containsKey(key)

    def __iter__(self):
        return iter(self._properties.keys())


class Domain:
    """Represents a weblogic domain"""

    def __init__(self, name, config, start_args, path, lock, cred, cluster=None):
        self.name = name
        self.config = config
        self.start_args = start_args
        self._path = path
        self._lock = lock
        self._cred = cred
        self.cluster = cluster
        self._encryption = ClearOrEncryptedService(getEncryptionService(self._path))

    def unlock(self):
        self._lock["edit_lock"] = "false"
        self._lock.save()

    def add_server(self, server, ip):
        self.config[server] = ip
        self.config.save()

    def remove_server(self, server):
        self.config.pop(server)
        self.config.save()

    def get_admin_server_ip(self, name):
        for server in [name, "oms_server01", "adminserver"]:
            ip = self.config[server]
            if ip:
                return ip
        return None

    def secret(self, secret):
        return self._encryption.decrypt(self._cred[secret])

    def update_admin_url(self):
        for _ in range(1, 5):
            self.config.reload()
            admin_server_ip = self.config["adminserver"]
            if admin_server_ip:
                break
            time.sleep(10)

        admin_url = "t3s://" + admin_server_ip + ":7002"
        self.config["admin_url"] = admin_url
        self.config.save()

    def get_server_from_ip(self, ip):
        servers = [key for key in self.config if self.config[key] == ip]
        if not servers:
            return None
        return servers[0]


DOMAIN_APP = Domain(
    name="app",
    path="/u01/app/oracle/config_oms/domains/oms_app",
    config=PyProperties(
        file="/u01/app/oracle/config/userdata/oms_app.config",
        comment="This is oms_app properties file",
    ),
    cred=PyProperties(
        file="/u01/app/oracle/config/userdata/cred_app.properties",
    ),
    lock=PyProperties(
        file="/u01/app/oracle/config/userdata/common/oms_app_lock.config",
        comment="This is oms_app lock properties file",
    ),
    start_args=[
        "-Xms8192m",
        "-Xmx8192m",
        "-XX:PermSize=2048m",
        "-XX:MaxPermSize=2048m",
        "-XX:+HeapDumpOnOutOfMemoryError",
        "-XX:HeapDumpPath=/u01/app/oracle/config_oms/domains/oms_app/servers/dumps/${HOSTNAME}.hprof",
        "-XX:+PrintClassHistogram",
        "-DDLOCK_LOG_DIR=/opt/ssfs/runtime/logs/ddlock",
        "-DLOGFILE=/opt/ssfs/runtime/logs/sci.log",
        "-DUseSunHttpsHandler=true",
        "-Denv_folder=dev",
        "-Dvendor=weblogic",
        "-Dfile.encoding=UTF-8",
        "-Dlog4j2.formatMsgNoLookups=true",
        "-Dsci.opsproxy.disable=Y",
        "-DuiExtensibilityMode=false",
        "-DvendorFile=/opt/ssfs/runtime/properties/servers.properties",
        "-Dweblogic.j2ee.application.tmpDir=/u01/app/wls_app_tmp",
        "-Dweblogic.oif.serialFilterMode=disable",
        "-Dweblogic.security.SSL.allowSmallRSAExponent=true",
        "-Dwufdevmode=false",
    ],
)

DOMAIN_JMS = Domain(
    name="jms",
    path="/u01/app/oracle/config_jms/domains/oms_jms",
    config=PyProperties(
        file="/u01/app/oracle/config/userdata/oms_jms.config",
        comment="This is oms_jms properties file",
    ),
    cred=PyProperties(
        file="/u01/app/oracle/config/userdata/cred_jms.properties",
    ),
    lock=PyProperties(
        file="/u01/app/oracle/config/userdata/common/oms_jms_lock.config",
        comment="This is oms_jms lock properties file",
    ),
    start_args=[
        "-Xms10240m",
        "-Xmx10240m",
        "-Xmn3072m",
        "-XX:MaxPermSize=2048m",
    ],
    cluster="jms_cluster01",
)

LOG = Logging()


class WebLogicClient:
    """A weblogic client"""

    def __init__(self):
        self._config_ssl()

    def _config_ssl(self):
        LOG.info("Configure SSL")
        System.setProperty("weblogic.security.SSL.ignoreHostnameVerification", "true")
        System.setProperty("weblogic.security.TrustKeyStore", "CustomTrust")
        System.setProperty(
            "weblogic.security.CustomTrustKeyStoreFileName",
            "/u01/app/oracle/config/common/security/cacerts",
        )

    def connect(self, username, password, admin_url):
        connect(username, password, admin_url)

    def disconnect(self):
        disconnect()

    def create_machine(self, name, address):
        machine_name = self.machine_name(name)
        LOG.info("create machine: " + machine_name)

        self._change_tree("domainConfig")
        machine = getMBean("/Machines/" + machine_name)
        if machine:
            LOG.warning("machine: " + machine_name + " already exists")
            return

        self._start_edit()
        machine = cmo.createUnixMachine(machine_name)
        machine.getNodeManager().setNMType("SSL")
        machine.getNodeManager().setListenAddress(address)
        self._activate()

    def destroy_machine(self, name):
        machine_name = self.machine_name(name)
        LOG.info("destroy machine: " + machine_name)

        self._change_tree("domainConfig")
        machine = getMBean("/Machines/" + machine_name)
        if not machine:
            LOG.warning("machine: " + machine_name + " not found")
            return

        self._start_edit()
        machine = getMBean("/Machines/" + machine_name)
        editService.getConfigurationManager().removeReferencesToBean(machine)
        cmo.destroyMachine(machine)
        self._activate()

    def create_server(
        self,
        name,
        start_args,
        ks_identity_password,
        ks_trust_password,
        ks_phrase,
        https_keepalive,
        cluster=None,
    ):
        LOG.info("create server: " + name)
        self._change_tree("domainConfig")
        server = getMBean("/Servers/" + name)
        if server:
            LOG.warning("server: " + name + " already exists")
            return

        self._start_edit()
        server = cmo.createServer(name)
        server.setListenPort(8001)
        server.setListenAddress("")
        if cluster:
            server.setCluster(getMBean("/Clusters/" + cluster))
            server.setMaxMessageSize(70000000)
        else:
            server.setStagingMode("nostage")
            server.setCluster(None)

        # Enable and Attach Identity/Trust KeyStores.
        server.setCustomIdentityKeyStorePassPhrase(ks_identity_password)
        server.setCustomIdentityKeyStoreType("JKS")
        server.setListenPortEnabled(True)
        server.setCustomTrustKeyStorePassPhrase(ks_trust_password)
        server.setCustomTrustKeyStoreType("JKS")
        server.setJavaCompiler("javac")
        server.setClientCertProxyEnabled(False)
        server.setKeyStores("CustomIdentityAndCustomTrust")
        server.setCustomTrustKeyStoreFileName(
            "/u01/app/oracle/config/common/security/cacerts"
        )
        server.setCustomIdentityKeyStoreFileName(
            "/u01/app/oracle/config/common/security/wlslululemon.jks"
        )

        # Enable SSL and Attach the keystore.
        ssl = getMBean("/Servers/" + name + "/SSL/" + name)
        ssl.setEnabled(True)
        ssl.setListenPort(8002)
        ssl.setHostnameVerificationIgnored(True)
        ssl.setHostnameVerifier(None)
        ssl.setServerPrivateKeyAlias("wls_oms")
        ssl.setEnabled(True)
        ssl.setInboundCertificateValidation("BuiltinSSLValidationOnly")
        ssl.setSSLRejectionLoggingEnabled(True)
        ssl.setAllowUnencryptedNullCipher(False)
        ssl.setExportKeyLifespan(500)
        ssl.setTwoWaySSLEnabled(False)
        ssl.setOutboundCertificateValidation("BuiltinSSLValidationOnly")
        ssl.setClientCertificateEnforced(False)
        ssl.setServerPrivateKeyPassPhrase(ks_phrase)
        ssl.setUseServerCerts(False)

        # Set HttpsKeepAliveSecs
        LOG.info("set HttpsKeepAliveSecs to: " + str(https_keepalive))
        web_server = getMBean("/Servers/" + name + "/WebServer/" + name)
        web_server.setHttpsKeepAliveSecs(int(https_keepalive))

        # Set server start argument
        server_start = getMBean("/Servers/" + name + "/ServerStart/" + name)
        server_start.setArguments(start_args)

        # Associated with a node manager.
        machine = getMBean("/Machines/" + self.machine_name(name))
        server.setMachine(machine)
        self._activate()

    def destroy_server(self, name):
        LOG.info("destroy server: " + name)
        self._change_tree("domainConfig")
        server = getMBean("/Servers/" + name)
        if not server:
            LOG.warning("server: " + name + " not found")
            return

        self._start_edit()
        server = getMBean("/Servers/" + name)
        server.setMachine(None)
        editService.getConfigurationManager().removeReferencesToBean(server)
        cmo.destroyServer(server)
        self._activate()

    def start_server(self, name):
        LOG.info("start server: " + name)
        self._change_tree("domainRuntime")
        life_cycle_runtime = getMBean("/ServerLifeCycleRuntimes/" + name)
        if not life_cycle_runtime:
            LOG.warning("server: " + name + " not found")
            return

        if life_cycle_runtime.getState() == ServerStates.RUNNING:
            LOG.warning("server: " + name + " already running")
            return

        start(name, "Server")

    def shutdown_server(self, name):
        LOG.info("shutdown server: " + name)

        self._change_tree("domainConfig")
        server = getMBean("/Servers/" + name)
        if not server:
            LOG.warning("server: " + name + " not found")
            return

        self._change_tree("domainRuntime")
        life_cycle_runtime = getMBean("/ServerLifeCycleRuntimes/" + server.getName())
        if life_cycle_runtime.getState() != ServerStates.RUNNING:
            LOG.warning("server: " + name + " not running")
            return

        shutdown(server.getName(), server.getType(), force="true")

    def deploy_application(self, name, server_name):
        ear_file = (
            "/u01/app/oracle/config_oms/domains/oms_app/applications/" + name + ".ear"
        )
        LOG.info("deploy application: " + ear_file)

        self._start_edit()
        progress = deploy(name, path=ear_file, targets=server_name, stageMode="nostage")
        progress.printStatus()
        self._activate(timeout=720000)

    def create_file_store(self, name):
        file_store_name = self.file_store_name(name)
        LOG.info("create file store: " + file_store_name)

        self._change_tree("domainConfig")
        filestore = getMBean("/FileStores/" + file_store_name)
        if filestore:
            LOG.warning("file store: " + file_store_name + " already exists")
            return

        self._start_edit()
        filestore = cmo.createFileStore(file_store_name)
        filestore.setDirectory(
            "/u01/app/oracle/config_jms/domains/oms_jms/LuluFilestore"
        )

        migratable_target_name = self.migratable_target_name(name)
        migratable_target = cmo.lookupMigratableTarget(migratable_target_name)
        filestore.addTarget(migratable_target)
        self._activate()

    def destroy_file_store(self, name):
        file_store_name = self.file_store_name(name)
        LOG.info("destroy file store: " + file_store_name)

        self._change_tree("domainConfig")
        filestore = getMBean("/FileStores/" + file_store_name)
        if not filestore:
            LOG.warning("file store: " + file_store_name + " not found")
            return

        self._start_edit()
        filestore = getMBean("/FileStores/" + file_store_name)
        cmo.destroyFileStore(filestore)
        self._activate()

    def destroy_migratable_target(self, name):
        migratable_target_name = self.migratable_target_name(name)
        LOG.info("destroy migratable target: " + migratable_target_name)

        self._start_edit()
        target = cmo.lookupMigratableTarget(migratable_target_name)
        if not target:
            LOG.warning("migratable target: " + migratable_target_name + " not found")
            self._cancel_edit()
            return
        cmo.destroyMigratableTarget(target)
        self._activate()

    def create_jms_server(self, name):
        jms_server_name = self.jms_server_name(name)
        LOG.info("create jms server: " + jms_server_name)

        self._change_tree("domainConfig")
        jms_server = getMBean("/JMSServers/" + jms_server_name)
        if jms_server:
            LOG.warning("jms server: " + jms_server_name + " already exists")
            return

        self._start_edit()
        jms_server = cmo.createJMSServer(jms_server_name)
        filestore = getMBean("/FileStores/" + self.file_store_name(name))
        jms_server.setPersistentStore(filestore)
        target = cmo.lookupMigratableTarget(self.migratable_target_name(name))
        jms_server.addTarget(target)
        self._activate()

    def destroy_jms_server(self, name):
        jms_server_name = self.jms_server_name(name)
        LOG.info("destroy jms server: " + jms_server_name)

        self._change_tree("domainConfig")
        jms_server = getMBean("/JMSServers/" + jms_server_name)
        if not jms_server:
            LOG.warning("jms server: " + jms_server_name + " not found")
            return

        self._start_edit()
        jms_server = getMBean("/JMSServers/" + jms_server_name)
        cmo.destroyJMSServer(jms_server)
        self._activate()

    def create_saf_agent(self, name):
        saf_agent_name = self.saf_agent_name(name)
        LOG.info("create saf agent: " + saf_agent_name)

        self._change_tree("domainConfig")
        saf_agent = getMBean("/SAFAgents/" + saf_agent_name)
        if saf_agent:
            LOG.warning("saf agent: " + saf_agent_name + " already exists")
            return

        self._start_edit()
        agent = cmo.createSAFAgent(saf_agent_name)
        target = cmo.lookupMigratableTarget(self.migratable_target_name(name))
        agent.addTarget(target)
        filestore = getMBean("/FileStores/" + self.file_store_name(name))
        agent.setStore(filestore)
        agent.setServiceType("Sending-only")
        self._activate()

    def destroy_saf_agent(self, name):
        saf_agent_name = self.saf_agent_name(name)
        LOG.info("destroy saf agent: " + saf_agent_name)

        self._change_tree("domainConfig")
        saf_agent = getMBean("/SAFAgents/" + saf_agent_name)
        if not saf_agent:
            LOG.warning("saf agent: " + saf_agent_name + " not found")
            return

        self._start_edit()
        saf_agent = getMBean("/SAFAgents/" + saf_agent_name)
        cmo.destroySAFAgent(saf_agent)
        self._activate()

    def set_subdeployment_targets(self, subdeployment_path, targets):
        self._start_edit()
        subdeployment = getMBean(subdeployment_path)
        subdeployment.setTargets(targets)
        self._activate()

    def remove_subdeployment_target(self, subdeployment_path, target_name):
        LOG.info("remove target: " + subdeployment_path + "/Targets/" + target_name)
        self._start_edit()

        subdeployment = getMBean(subdeployment_path)
        if not subdeployment:
            LOG.warning("subdeployment: " + subdeployment_path + " not found")
            self._cancel_edit()
            return

        target = cmo.lookupTarget(target_name)
        if not target:
            LOG.warning("target: " + target_name + " not found")
            self._cancel_edit()
            return

        targets = [t.getName() for t in subdeployment.getTargets()]
        if target.getName() not in targets:
            LOG.warning(
                "target: " + target_name + " not found in " + subdeployment.getName()
            )
            self._cancel_edit()
            return

        subdeployment.removeTarget(target)
        self._activate()

    def get_saf_agents_targets(self):
        self._change_tree("edit")
        agents = cmo.getSAFAgents()
        agents = [x for x in agents if x.getName() != "ReliableWseeSAFAgent"]
        targets = [cmo.lookupTarget(agent.getName()) for agent in agents]
        return targets

    def get_jms_servers_targets(self):
        self._change_tree("edit")
        servers = cmo.getJMSServers()
        servers = [x for x in servers if x.getName() != "WseeJmsServer"]
        targets = [cmo.lookupTarget(server.getName()) for server in servers]
        return targets

    def machine_name(self, name):
        return "mc_" + name

    def file_store_name(self, name):
        return "LululFilestore." + name

    def migratable_target_name(self, name):
        return name + " (migratable)"

    def jms_server_name(self, name):
        return "LuluJMS." + name

    def saf_agent_name(self, name):
        return "SAF_Agent." + name

    def _change_tree(self, tree):
        if tree not in ["domainConfig", "domainRuntime", "edit", "serverConfig"]:
            raise ValueError()

        if pwd() == tree + ":/":
            return

        globals()[tree]()
        cd("/")

    def _start_edit(self):
        self._change_tree("edit")
        startEdit()

    def _cancel_edit(self):
        cancelEdit(defaultAnswer="y")

    def _activate(self, timeout=300000, block="true"):
        save()
        activate(timeout=timeout, block=block)



def target_jdbc_ds_to_server(self, ds_name, server_name):
    """Target a JDBC Data Source to a single Server (idempotent).
    Only call this for app domain per caller's logic.
    """
    try:
        # Work in edit tree
        self._start_edit()
        cd('/')
        ds = cmo.lookupJDBCSystemResource(ds_name)
        if ds is None:
            self._cancel_edit()
            LOG.warning("JDBC Data Source %s not found; skipping target attach" % ds_name)
            return

        srv = cmo.lookupServer(server_name)
        if srv is None:
            self._cancel_edit()
            LOG.warning("Server %s not found in domain config; cannot target DS" % server_name)
            return

        cd('/JDBCSystemResources/%s' % ds_name)
        targets = list(get('Targets') or [])
        me = ObjectName('com.bea:Name=%s,Type=Server' % server_name)

        if me in targets:
            # Keep edit session clean; no change needed
            self._cancel_edit()
            LOG.info("JDBC DS %s already targeted to %s" % (ds_name, server_name))
            return
        else:
            targets.append(me)
            set('Targets', jarray.array(targets, ObjectName))
            self._activate(block='true')
            LOG.info("Targeted JDBC DS %s to server %s" % (ds_name, server_name))
    except:
        try:
            self._cancel_edit()
        except:
            pass
        LOG.error("Failed to target JDBC DS %s to server %s" % (ds_name, server_name))


class CLI:
    """Represents the application"""

    def __init__(self):
        parser = ArgumentParser()
        parser.add_argument(
            "--action", required=True, choices=["create", "delete"], help="action"
        )
        parser.add_argument(
            "--domain", required=True, choices=["app", "jms"], help="weblogic domain"
        )
        parser.add_argument("--host", required=True, help="server ip address")
        parser.add_argument(
            "--app",
            choices=["isf", "smcfs_api", "smcfs_others", "wsc", "smcfs_icc"],
            help="earfile name",
        )
        parser.add_argument("--server", help="server name")
        parser.add_argument("--server-extra-args", help="extra jvm arguments")
        parser.add_argument("--https-keepalive", default=60, help="HttpsKeepAliveSecs value")
        args = parser.parse_args()

        if args.action in ["create"] and args.server is None:
            LOG.error("server is required when action is " + args.action)
            args.print_help()

        if args.action in ["create"] and args.domain == "app" and args.app is None:
            LOG.error("app is required when creating a server in app domain")
            args.print_help()

        if args.domain == "jms":
            domain = DOMAIN_JMS

        if args.domain == "app":
            domain = DOMAIN_APP

        if args.domain == "app" and args.action in ["create", "start"]:
            jms_ip = DOMAIN_JMS.get_admin_server_ip(args.server)
            if not jms_ip:
                LOG.fatal("No jms servers found")

            start_arg = "-Dsci.naming.provider.url=t3s://" + jms_ip + ":8002"
            domain.start_args.append(start_arg)
            domain.start_args.append("-Dserver_name=" + args.server)

        if args.server_extra_args:
            domain.start_args.append(args.server_extra_args)

        domain.update_admin_url()

        self.args = args
        self.domain = domain
        self.weblogic = WebLogicClient()

        # Only JMS_MODULEJmsSystemModule is in scope, SupplychainJMSModuleJmsSystemModule is not in scope
        self.saf_subdeployments = [
            "/JMSSystemResources/JMS_MODULEJmsSystemModule/SubDeployments/SAF_AgentSubDeployment",
            "/JMSSystemResources/SupplychainJMSModuleJmsSystemModule/SubDeployments/SAF_AgentSubDeployment",
        ]

        self.jms_subdeployments = [
            "/JMSSystemResources/B2BJMSModuleJmsSystemModule/SubDeployments/B2BJMSModuleSubDeployment",
            "/JMSSystemResources/JMS_MODULEJmsSystemModule/SubDeployments/JMS_MODULESubDeployment",
            "/JMSSystemResources/SupplychainJMSModuleJmsSystemModule/SubDeployments/SupplychainJMSModuleSubDeployment",
        ]

    def run(self):
        self.weblogic.connect(
            username="weblogic",
            password=self.domain.secret("weblogicPassword"),
            admin_url=self.domain.config["admin_url"],
        )

        if self.args.action == "create":
            self.create(self.args.server, self.args.host, self.args.app, self.args.https_keepalive)

        if self.args.action == "delete":
            self.delete(self.args.host)

        self.weblogic.disconnect()

    def create(self, server_name, ip, app, https_keepalive):
        self.domain.add_server(server_name, ip)
        self.weblogic.create_machine(server_name, ip)
        self.weblogic.create_server(
            name=server_name,
            start_args=" ".join(self.domain.start_args),
            ks_identity_password=self.domain.secret("ksIdentityPassword"),
            ks_trust_password=self.domain.secret("ksTrustPassword"),
            ks_phrase=self.domain.secret("ksPhrase"),
            cluster=self.domain.cluster,
            https_keepalive=https_keepalive
        )

        # Ensure JDBC Data Source "OMSDS" is targeted to THIS new server (app domain only)
        if self.domain.name == "app":
            # Idempotent; safe to run on every creation
            self.weblogic.target_jdbc_ds_to_server("OMSDS", server_name)


        if self.domain.name == "app":
            self.weblogic.start_server(server_name)
            self.weblogic.deploy_application(app, server_name)

        if self.domain.name == "jms":
            self.weblogic.create_file_store(server_name)

            self.weblogic.create_jms_server(server_name)
            targets = self.weblogic.get_jms_servers_targets()
            for subdeployment in self.jms_subdeployments:
                self.weblogic.set_subdeployment_targets(subdeployment, targets)

            self.weblogic.create_saf_agent(server_name)
            targets = self.weblogic.get_saf_agents_targets()
            for subdeployment in self.saf_subdeployments:
                self.weblogic.set_subdeployment_targets(subdeployment, targets)

            self.weblogic.start_server(server_name)

    def delete(self, ip):
        server_name = self.domain.get_server_from_ip(ip)
        if not server_name:
            LOG.error("host: " + ip + " not found in domain config file")
            return

        self.weblogic.shutdown_server(server_name)

        if self.domain.name == "jms":
            target = self.weblogic.saf_agent_name(server_name)
            for subdeployment in self.saf_subdeployments:
                self.weblogic.remove_subdeployment_target(subdeployment, target)
            self.weblogic.destroy_saf_agent(server_name)

            target = self.weblogic.jms_server_name(server_name)
            for subdeployment in self.jms_subdeployments:
                self.weblogic.remove_subdeployment_target(subdeployment, target)
            self.weblogic.destroy_jms_server(server_name)

            self.weblogic.destroy_file_store(server_name)
            self.weblogic.destroy_migratable_target(server_name)

        self.weblogic.destroy_server(server_name)
        self.weblogic.destroy_machine(server_name)
        self.domain.remove_server(server_name)


def main():
    cli = CLI()
    cli.run()


main()
