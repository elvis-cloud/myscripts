from __future__ import print_function

from java.util import Hashtable
from javax.naming import Context, InitialContext
from javax.jms import ConnectionFactory
from java.lang.reflect import Modifier


PROVIDER_URL = "t3s://server-jms.omega2.aws.lllint.com:8002"  
CF_JNDI_NAME = "OMS_QCF"                                    


def banner(msg):
    print("\n>>> {0}\n".format(msg))

def dump_getters(obj, label):
    print("\n--- Introspection of {0} ({1}) ---".format(label, obj.getClass().getName()))
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
                    "Host" in sval or
                    "host" in sval or
                    ":" in sval):  # ports/hosts often show as host:port
                    print("{0} = {1}".format(name, sval))
            except Exception as e:
                # Some getters throw; that's fine, skip them
                pass
    print("--- end introspection ---\n")

# 1. Build InitialContext like the agent would (no creds)
banner("Building InitialContext to {0}".format(PROVIDER_URL))

env = Hashtable()
env.put(Context.INITIAL_CONTEXT_FACTORY, "weblogic.jndi.WLInitialContextFactory")
env.put(Context.PROVIDER_URL, PROVIDER_URL)

ctx = InitialContext(env)
banner("InitialContext created successfully")

# 2. Lookup the ConnectionFactory
cf_obj = ctx.lookup(CF_JNDI_NAME)
banner("Lookup complete for {0}".format(CF_JNDI_NAME))

print("ConnectionFactory impl class: {0}".format(cf_obj.getClass().getName()))
print("ConnectionFactory toString(): {0}".format(cf_obj.toString()))

# 3. Dump CF internals via getters
dump_getters(cf_obj, "ConnectionFactory")

# 4. Try to create a JMS Connection (anonymous)
if isinstance(cf_obj, ConnectionFactory):
    try:
        conn = cf_obj.createConnection()
        banner("Successfully created JMS Connection of type: {0}".format(conn.getClass().getName()))
        print("Connection toString(): {0}".format(conn.toString()))
        dump_getters(conn, "Connection")
        conn.close()
        banner("Connection closed cleanly.")
    except Exception as e:
        banner("Could not createConnection() anonymously, got exception:")
        print(e)
else:
    banner("WARNING: Looked-up object is not a javax.jms.ConnectionFactory")

banner("Done.")
