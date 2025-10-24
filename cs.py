from java.util import Hashtable
from javax.naming import Context, InitialContext
from javax.jms import ConnectionFactory


PROVIDER_URL = "t3s://oms-jms.mycompany.internal:8001"   # or t3://..., same as agent
CF_JNDI_NAME = "jms/OMSConnectionFactory"                # same CF JNDI name the agent uses

def p(msg):
    print "\n>>> %s\n" % msg

p("Building InitialContext to %s" % PROVIDER_URL)

env = Hashtable()
env.put(Context.INITIAL_CONTEXT_FACTORY, "weblogic.jndi.WLInitialContextFactory")
env.put(Context.PROVIDER_URL, PROVIDER_URL)


ctx = InitialContext(env)
p("InitialContext created successfully")

obj = ctx.lookup(CF_JNDI_NAME)
p("Lookup complete for %s" % CF_JNDI_NAME)

p("ConnectionFactory impl class: %s" % obj.getClass().getName())
p("ConnectionFactory toString(): %s" % obj.toString())

if isinstance(obj, ConnectionFactory):
    cf = obj
    try:
        conn = cf.createConnection()  
        p("Successfully created JMS Connection of type: %s" % conn.getClass().getName())
        p("Connection toString(): %s" % conn.toString())
        conn.close()
        p("Connection closed cleanly.")
    except Exception, e:
        p("Could not createConnection() anonymously. Exception:")
        p(e)
else:
    p("WARNING: Looked up object is not a javax.jms.ConnectionFactory")

p("Done.")
