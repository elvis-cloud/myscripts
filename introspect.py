# Introspect JMS ConnectionFactory and Connection objects (WLST-safe)

from java.util import Hashtable
from javax.naming import Context, InitialContext
from javax.jms import ConnectionFactory
from java.lang.reflect import Modifier

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
PROVIDER_URL = "t3s://server-jms.omega2.aws.lllint.com:8002"
CF_JNDI_NAME = "OMS_QCF"
# <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

def banner(msg):
    print "\n>>> %s\n" % msg

def dump_getters(obj, label):
    print "\n--- Introspection of %s (%s) ---" % (label, obj.getClass().getName())
    methods = obj.getClass().getMethods()
    for m in methods:
        name = m.getName()
        if name.startswith("get") and m.getParameterTypes().length == 0 and Modifier.isPublic(m.getModifiers()):
            try:
                val = m.invoke(obj, None)
                if val is None:
                    continue
                sval = str(val)
                if len(sval) > 1500:
                    sval = sval[:1500] + "...(truncated)"
                # Only print interesting fields
                if ("url" in name.lower() or
                    "address" in name.lower() or
                    "provider" in name.lower() or
                    "cluster" in name.lower() or
                    "member" in name.lower() or
                    "server" in name.lower() or
                    "target" in name.lower() or
                    "load" in name.lower() or
                    "affinity" in name.lower() or
                    "failover" in name.lower() or
                    "balance" in name.lower() or
                    ":" in sval):
                    print "%s = %s" % (name, sval)
            except Exception, e:
                pass
    print "--- end introspection ---\n"

banner("Building InitialContext to %s" % PROVIDER_URL)
env = Hashtable()
env.put(Context.INITIAL_CONTEXT_FACTORY, "weblogic.jndi.WLInitialContextFactory")
env.put(Context.PROVIDER_URL, PROVIDER_URL)

ctx = InitialContext(env)
banner("InitialContext created successfully")

cf_obj = ctx.lookup(CF_JNDI_NAME)
banner("Lookup complete for %s" % CF_JNDI_NAME)

print "ConnectionFactory impl class: %s" % cf_obj.getClass().getName()
print "ConnectionFactory toString(): %s" % cf_obj.toString()

dump_getters(cf_obj, "ConnectionFactory")

if isinstance(cf_obj, ConnectionFactory):
    try:
        conn = cf_obj.createConnection()
        banner("Successfully created JMS Connection of type: %s" % conn.getClass().getName())
        print "Connection toString(): %s" % conn.toString()
        dump_getters(conn, "Connection")
        conn.close()
        banner("Connection closed cleanly.")
    except Exception, e:
        banner("Could not createConnection() anonymously.")
        print e
else:
    banner("WARNING: Looked-up object is not a javax.jms.ConnectionFactory")

banner("Done.")
