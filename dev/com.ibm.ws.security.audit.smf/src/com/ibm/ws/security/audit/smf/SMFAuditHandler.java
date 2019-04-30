/*******************************************************************************
 * Copyright (c) 2018, 2019 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.security.audit.smf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStoreException;
import java.security.PrivilegedActionException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.ComponentException;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;

import com.ibm.json.java.JSONArray;
import com.ibm.json.java.JSONObject;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.security.audit.AuditConstants;
import com.ibm.websphere.security.audit.AuditEvent;
import com.ibm.websphere.security.audit.InvalidConfigurationException;
import com.ibm.ws.common.internal.encoder.Base64Coder;
import com.ibm.ws.config.xml.internal.nester.Nester;
import com.ibm.ws.logging.collector.LogFieldConstants;
import com.ibm.ws.logging.data.GenericData;
import com.ibm.ws.logging.data.KeyValuePair;
import com.ibm.ws.logging.data.KeyValueStringPair;
import com.ibm.ws.security.audit.event.AuditMgmtEvent;
import com.ibm.ws.ssl.KeyStoreService;
import com.ibm.wsspi.collector.manager.BufferManager;
import com.ibm.wsspi.collector.manager.CollectorManager;
import com.ibm.wsspi.collector.manager.Handler;
import com.ibm.wsspi.collector.manager.SynchronousHandler;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;
import com.ibm.wsspi.kernel.service.utils.AtomicServiceReference;
import com.ibm.wsspi.security.audit.AuditEncryptionException;
import com.ibm.wsspi.security.audit.AuditService;
import com.ibm.wsspi.security.audit.AuditSigningException;


@Component(service = Handler.class, configurationPid = "com.ibm.ws.security.audit.smf.handler", configurationPolicy = ConfigurationPolicy.OPTIONAL, property = "service.vendor=IBM", immediate = true)

public final class SMFAuditHandler implements SynchronousHandler {
    private final static TraceComponent tc = Tr.register(SMFAuditHandler.class);
    
    private volatile CollectorManager collectorMgr;

    private static final String KEY_EXECUTOR_SERVICE = "executorSrvc";
    private final AtomicServiceReference<ExecutorService> executorSrvcRef = new AtomicServiceReference<ExecutorService>(KEY_EXECUTOR_SERVICE);

    private volatile Future<?> handlerTaskRef = null;

    private volatile BufferManager bufferMgr = null;

    private final String KEY_LOCATION_ADMIN = "locationAdmin";
    private final AtomicServiceReference<WsLocationAdmin> locationAdminRef = new AtomicServiceReference<WsLocationAdmin>(KEY_LOCATION_ADMIN);

    private static final String KEY_AUDIT_SERVICE = "auditService";
    protected final AtomicServiceReference<AuditService> auditServiceRef = new AtomicServiceReference<AuditService>(KEY_AUDIT_SERVICE);


    //private AuditEventSettings _aes;
    private ConcurrentHashMap<String,ConcurrentHashMap<String,String>> auditFilterSettings = new ConcurrentHashMap<String,ConcurrentHashMap<String,String>>();
    private ConcurrentHashMap<String,String> auditOutcomeSettings = new ConcurrentHashMap<String,String>();
    private static AuditService auditService = null;
    private String activeUserRegistry = null;
    private int sequenceNumber = 0;
    private RAuditxWrapper rauditx = null;
    private boolean verbose = false;
    private static Object syncRauditxObject = new Object();
    private int fieldLengthLimit = 0;
    private Map<String, Object> thisConfiguration;
    List<Map<String, Object>> configuredEvents = null;
    private String[] events = null;
    private static Object syncSeqNum = new Object();
    private int auditEventType = -1;
    
    // SMF event codes
    
    static public final int SMF_CONFIG_SNAPSHOT = 1;
    static public final int SMF_SECURITY_AUDIT_MGMT = 2;
    static public final int SMF_SECURITY_MEMBER_MGMT = 3;
    static public final int SMF_SECURITY_SERVICE_MGMT = 4;
    static public final int SMF_SECURITY_SESSION_LOGIN = 5;
    static public final int SMF_SECURITY_SESSION_LOGOUT = 6;
    static public final int SMF_SECURITY_SESSION_EXPIRY = 7
    static public final int SMF_SECURITY_API_AUTHN = 8;
    static public final int SMF_SECURITY_API_AUTHN_TERMINATE = 9;
    static public final int SMF_SECURITY_ROLE_MAPPING = 10;
    static public final int SMF_SECURITY_AUTHN = 11;
    static public final int SMF_SECURITY_AUTHN_DELEGATION = 12;
    static public final int SMF_SECURITY_AUTHZ_DELEGATION = 13;
    static public final int SMF_SECURITY_AUTHN_TERMINATE = 14;
    static public final int SMF_SECURITY_AUTHN_FAILOVER = 15;
    static public final int SMF_SECURITY_AUTHZ = 16;
    static public final int SMF_SECURITY_SIGNING = 17;
    static public final int SMF_SECURITY_ENCRYPTION = 18;
    static public final int SMF_SECURITY_RESOURCE_ACCESS = 19;
    static public final int SMF_SECURITY_MGMT_KEY = 20;
    static public final int SMF_SECURITY_RUNTIME_KEY = 21;
    static public final int SMF_SECURITY_JMS_AUTHN = 22;
    static public final int SMF_SECURITY_JMS_AUTHZ = 23;
    static public final int SMF_SECURITY_JMS_AUTHN_TERMINATE = 24;
    static public final int SMF_SECURITY_JMS_CLOSED_CONNECTION = 25;
    static public final int SMF_SECURITY_SAF_AUTHZ_DETAILS = 26;
    static public final int SMF_MX_MBEAN = 27;
    static public final int SMF_JMX_NOTIFICATION = 28;
    static public final int SMF_JMX_MBEAN_ATTRIBUTES = 29;
    static public final int SMF_JMX_MBEAN_REGISTER = 30;
    static public final int SMF_JMS = 31;
    static public final int SMF_APPLICATION_TOKEN_MANAGEMENT = 32;
    static public final int SMF_CUSTOM = 33;

    private static ConcurrentHashMap aOutcome = new ConcurrentHashMap();
    
    private final List<String> sourceIds = new ArrayList<String>() {
        {
            add(AuditService.AUDIT_SOURCE_NAME + AuditService.AUDIT_SOURCE_SEPARATOR + AuditService.AUDIT_SOURCE_LOCATION);
        }
    };


    public SMFAuditHandler() {
    }
    
    @Activate
    protected void activate(ComponentContext cc)  {
        Tr.info(tc, "AUDIT_SMF_HANDLER_STARTING");
        locationAdminRef.activate(cc);
        executorSrvcRef.activate(cc);
        auditServiceRef.activate(cc);

        Map<String, Object> configuration = (Map) cc.getProperties();
        thisConfiguration = configuration;
        
        if (configuration != null && !configuration.isEmpty()) {
            configuredEvents = Nester.nest("events", configuration);
            if (tc.isDebugEnabled()) {
                Tr.debug(tc, "configuredEvents being sent to AuditService: " + configuredEvents.toString());
            }
        }

        auditService = auditServiceRef.getService();
        try {
            auditService.registerEvents(getHandlerName(), configuredEvents);
        } catch (InvalidConfigurationException e) {
            locationAdminRef.deactivate(cc);
            executorSrvcRef.deactivate(cc);
            auditServiceRef.deactivate(cc);
            cc.disableComponent((String) configuration.get(org.osgi.framework.Constants.SERVICE_PID));
            Tr.info(tc, "AUDIT_SMF_HANDLER_STOPPED");
            throw new ComponentException("Caught invalidConfigurationException");
        }


        Tr.info(tc, "AUDIT_SMF_HANDLER_READY");

    }

    @Deactivate
    protected void deactivate(ComponentContext cc) {

        auditService.unRegisterEvents(getHandlerName());
        locationAdminRef.deactivate(cc);
        executorSrvcRef.deactivate(cc);
        auditServiceRef.deactivate(cc);
        Tr.info(tc, "AUDIT_SMF_HANDLER_STOPPED");

    }
    
    /** {@inheritDoc} */
    public String getHandlerName() {
        return AuditService.AUDIT_SMF_HANDLER_NAME;
    }

    /** {@inheritDoc} */
    @Override
    public void init(CollectorManager collectorMgr) {
        try {
            this.collectorMgr = collectorMgr;
            this.collectorMgr.subscribe(this, sourceIds);
        } catch (Exception e) {

        }

    }

    /** {@inheritDoc} */

    @Override
    public void setBufferManager(String sourceId, BufferManager bufferMgr) {
        auditService.sendEvent(null);
    }

    /** {@inheritDoc} */

    @Override
    public void unsetBufferManager(String sourceId, BufferManager bufferMgr) {
        if (auditService.isAuditRequired(AuditConstants.SECURITY_AUDIT_MGMT,
                                         AuditConstants.SUCCESS)) {
            AuditMgmtEvent av = new AuditMgmtEvent(thisConfiguration, "AuditHandler:" + auditService.AUDIT_SMF_HANDLER_NAME, "stop");
            auditService.sendEvent(av);
            av = new AuditMgmtEvent(thisConfiguration, "AuditService", "stop");
            auditService.sendEvent(av);
        }

    }


    /**
      * <p>
      * The <code>init</code> method allows an <code>AuditServiceProvider</code> implementation to
      * initialize its internal security auditing configuration using the properties and context object.
      * The <code>init</code> method is invoked once during AuditService initialization.
      * </p>
      * <p>
      * The properties, context and keyProperties objects should be treated as READ-ONLY and must not be modified by the 
      * <code>AuditServiceProvider</code> implementation.
      * </p>
      * @param A String object represents the name of this AuditServiceProvider.
      * @param A Map properties object that contains the custom properties which can be defined in the 
      * the admin console, or by using wsadmin scripting tool.
      * @param A Map object that contains the encrypt/sign properties. 
      * @param A Map object that contains the properties associated with the keystore created by the Auditor
      * containing the public certificate created by the Auditor which is used for encryption.
      * @exception ProviderFailureException may be thrown if the audit service provider fails to initialize 
      */ 
/*    public void   init(String name, Map properties, Map secProps, Map keyProperties) throws ProviderFailureException
    {
        if (tc.isEntryEnabled()) Tr.entry(tc, "init: " + name);

        // Get a handle to the auditService
        if (auditService == null) {
            auditService = ContextManagerFactory.getInstance().getAuditService();
        }


        SecurityConfig security = SecurityObjectLocator.getSecurityConfig();
        activeUserRegistry = security.getActiveUserRegistry().getType();

        _aes = new AuditEventSettings();
        auditFilterSettings = _aes.getFilterSettings();
        auditOutcomeSettings = _aes.getOutcomeSettings();

        if (tc.isEntryEnabled()) Tr.exit(tc, "init");

    }
*/
    /**
     * Produce a JSON String for the given audit event
     *
     * @return
     */
    private String mapToJSONString(Map<String, Object> eventMap) {
        JSONObject jsonEvent = new JSONObject();
        String jsonString = null;
        map2JSON(jsonEvent, eventMap);
        try {
            jsonString = jsonEvent.serialize(true).replaceAll("\\\\/", "/");
        } catch (IOException e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Unexpected error converting AuditEvent to JSON String", e);
            }
        }
        return jsonString;
    }

    /**
     * Given a Map, add the corresponding JSON to the given JSONObject.
     *
     * @param jo - JSONObject
     * @param map - Java Map object
     */
    private JSONObject map2JSON(JSONObject jo, Map<String, Object> map) {
        for (Entry<String, Object> entry : map.entrySet()) {
            String subkeys = null;
            String key = null;
            Object value = entry.getValue();
            int i = entry.getKey().indexOf(".");
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "raw key, index", new Object[] { entry.getKey(), i });
            }
            if (i > -1) {
                subkeys = entry.getKey().substring(i + 1);
                key = entry.getKey().substring(0, i);
            } else {
                key = entry.getKey();
            }
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "key, subkeys", new Object[] { key, subkeys });
            }
            if (subkeys == null) { // simple key
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "simple key: " + entry.getKey());
                }
                if (value == null) {
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "value is null");
                    }
                    jo.put(key, "null");
                } else if (value instanceof Map) { // value is a Map
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "value is a Map, calling map2JSON", value);
                    }
                    jo.put(key, map2JSON(new JSONObject(), (Map<String, Object>) value));
                } else if (value.getClass().isArray()) { // value is an array
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "value is an array, calling array2JSON", value);
                    }
                    jo.put(key, array2JSON(new JSONArray(), (Object[]) value));
                } else { // else value is a "simple" value
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "simple value, adding to jo", value);
                    }
                    jo.put(key, value);
                }
            } else { // compound key
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "compound key: " + entry.getKey());
                }
                JSONObject jsonSubstruc = (JSONObject) jo.get(key);
                if (jsonSubstruc == null) {
                    jsonSubstruc = new JSONObject();
                    jo.put(key, jsonSubstruc);
                }
                Map<String, Object> submap = new TreeMap<String, Object>();
                submap.put(subkeys, value);
                map2JSON(jsonSubstruc, submap);
            }
        }
        return jo;
    }

    /**
     * Given a Java array, add the corresponding JSON to the given JSONArray object
     *
     * @param ja - JSONArray object
     * @param array - Java array object
     */
    private JSONArray array2JSON(JSONArray ja, Object[] array) {
        for (int i = 0; i < array.length; i++) {
            // array entry is a Map
            if (array[i] instanceof Map) {
                //if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                //    Tr.debug(tc, "array entry is a Map, calling map2JSON", array[i]);
                //}
                ja.add(map2JSON(new JSONObject(), (Map<String, Object>) array[i]));
            }
            // array entry is an array
            else if (array[i].getClass().isArray()) {
                //if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                //    Tr.debug(tc, "array entry is a array, calling array2JSON", array[i]);
                //}
                ja.add(array2JSON(new JSONArray(), (Object[]) array[i]));
            }
            // else array entry is a "simple" value
            else {
                //if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                //    Tr.debug(tc, "array entry is a simple value, adding to ja", array[i]);
                //}
                ja.add(array[i]);
            }
        }
        return ja;
    }
    
    /** {@inheritDoc} */
    public void setEvents(Object value) {
        this.events = ((String) value).split(", ");
    }

    /** {@inheritDoc} */
    public String[] getEvents() {
        return this.events;
    }

    /** {@inheritDoc} */
    @Override
    public void synchronousWrite(Object arg) {
        synchronized (syncSeqNum) {

            try {
                AuditEvent event = new AuditEvent();
                GenericData gdo = (GenericData) arg;

                ArrayList<KeyValuePair> list = gdo.getPairs();
                Iterator<KeyValuePair> iter = list.iterator();
                while (iter.hasNext()) {
                    Object objectPair = iter.next();
                    if (objectPair instanceof KeyValueStringPair) {
                        if (!((KeyValuePair) objectPair).getKey().equals(LogFieldConstants.IBM_DATETIME) &&
                            (!((KeyValuePair) objectPair).getKey().equals(LogFieldConstants.IBM_SEQUENCE))) {
                            event.set(((KeyValuePair) objectPair).getKey(), ((KeyValuePair) objectPair).getStringValue());
                        }
                    }
                }

                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Received event " + event.toString());
                }
                AuditService auditService = auditServiceRef.getService();
                if (auditService != null) {

                	String en = (String) event.getMap().get(AuditEvent.EVENTNAME);
                	String eo = (String) event.getMap().get(AuditEvent.OUTCOME);
                	if (auditService.isAuditRequired(en, eo)) {
                		synchronized(syncRauditxObject) {
                			rauditx = new RAuditxWrapper();

                			try {
                				// set the event outcome
                				if (eo.equals(AuditConstants.SUCCESS))
                					rauditx.setEventSuccess();
                				else
                					rauditx.setEventFailure();

                				// set the event code qualifier

                				if (eo.equals(AuditConstants.SUCCESS)) {
                					rauditx.setQualifier(0);
                				} else if (eo.equals(AuditConstants.INFO)) {
                					rauditx.setQualifier(1);
                				} else if (eo.equals(AuditConstants.WARNING)) {
                					rauditx.setQualifier(2);
                				} else if (eo.equals(AuditConstants.FAILURE)) {
                					rauditx.setQualifier(3);
                				} else if (eo.equals(AuditConstants.REDIRECT)) {
                					rauditx.setQualifier(4);
                				} else if (eo.equals(AuditConstants.DENIED)) {
                					rauditx.setQualifier(5);
                				} else if (eo.equals(AuditConstants.ERROR)) {
                					rauditx.setQualifier(6);
                				}


                				if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUTHN)) {
                					auditEventType = SMF_SECURITY_AUTHN_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUTHN_TERMINATE)) {
                					auditEventType = SMF_SECURITY_AUTHN_TERMINATE_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUTHN_FAILOVER)) {
                					auditEventType = SMF_SECURITY_AUTHN_FAILOVER_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUTHN_DELEGATION)) {
                					auditEventType = SMF_SECURITY_AUTHN_DELEGATION_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_API_AUTHN)) {
                					auditEventType = SMF_SECURITY_API_AUTHN_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_API_AUTHN_TERMINATE)) {
                					auditEventType = SMF_SECURITY_API_TERMINATE_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUTHZ)) {
                					auditEventType = SMF_SECURITY_AUTHZ_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_AUDIT_MGMT)) {
                					auditEventType = SMF_SECURITY_AUDIT_MGMT_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_MEMBER_MGMT)) {
                					auditEventType = SMF_SECURITY_MEMBER_MGMT_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_JMS_AUTHN)) {
                					auditEventType = SMF_SECURITY_JMS_AUTHN_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.SECURITY_JMS_AUTHZ)) {
                					auditEventType = SMF_SECURITY_JMS_AUTHZ_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.JMX_MBEAN)) {
                					auditEventType = SMF_JMX_MBEAN_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.JMX_MBEAN_ATTRIBUTES)) {
                					auditEventType = SMF_JMX_MBEAN_ATTRIBUTES_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.JMX_MBEAN_REGISTER)) {
                					auditEventType = SMF_JMX_MBEAN_REGISTER_CODE;
                				} else if (en.equalsIgnoreCase(AuditConstants.JMX_NOTIFICATION)) {
                					auditEventType = SMF_JMX_NOTIFICATION_CODE;
                				}

                				rauditx.setEvent(auditEventType);
                				// set the subType. This is a constant value for SMF Auditing
                				rauditx.setSubtype(5);

                				// set the FMID.  This is a constant value, per Z release
                				rauditx.setFmid("H28W700");

                				// always allow successes and failures to flow through.  This will allow
                				// us to bypass creating a racf class and forcing the z/OS auditor to do 
                				// a SETROPTS LOGOPTIONS(ALWAYS(class)) on that class
                				rauditx.setAlwaysLogSuccesses();
                				rauditx.setAlwaysLogFailures();

                				// - fill in data
                				
                                HashMap properties = (HashMap) event.getMap();

                                if (tc.isDebugEnabled()) {
                                    Tr.debug(tc, "properties: " + properties.toString());
                                }

/*
                                    String lastT = (String)properties.get(AuditConstants.LAST_EVENT_TRAIL_ID);
                                    if (verbose) {
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "lastEventTrailId: " + lastT);
                                        }
                                        if (lastT != null && lastT.length() != 0) {
                                            rauditx.addRelocateSection(100, lastT);
                                            if (tc.isDebugEnabled()) {
                                                Tr.debug(tc, "added lastEventTrailId");
                                            }
                                        }
                                    }

                                    if (lastT != null && lastT.length() > 0) {
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "eventTrailId: " + lastT);
                                        }
                                        rauditx.addRelocateSection(101, lastT);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added eventTrailId");
                                        }
                                    }

                                    String st = new String();
                                    
                                    String[] eventTrails = (String[])properties.get(AuditConstants.EVENT_TRAIL_ID);
                                    if (eventTrails != null && eventTrails.length != 0) {
                                       st = "";
                                       for (int  i = 0; i < eventTrails.length; i++) {
                                           st = st.concat(eventTrails[i] = " , ");
                                       }
                                       if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);
                                       rauditx.addRelocateSection(101, st);
                                    }
                                    

                                    Date createT = (Date)properties.get(AuditConstants.CREATION_TIME);
                                    if (createT != null) {
                                        rauditx.addRelocateSection(102, createT.toString());
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added creation time: " + createT.toString());
                                        }
                                    }


                                    Long gID = (Long)properties.get(AuditConstants.GLOBAL_INSTANCE_ID);
                                    if (gID != null) {
                                        rauditx.addRelocateSection(103, gID.toString());
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added gID: " + gID.toString());
                                        }
                                    }


                                    String sID = (String)properties.get(AuditConstants.SESSION_ID);
                                    if (sID != null && sID.length() != 0) {
                                        rauditx.addRelocateSection(105, sID);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added session ID: " + sID);
                                        }
                                    }

                                    String rA = (String)properties.get(AuditConstants.REMOTE_ADDR);
                                    if (rA != null && rA.length() != 0) {
                                        rauditx.addRelocateSection(106, rA);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added remote address: " + rA);
                                        }
                                    }

                                    String rP = (String)properties.get(AuditConstants.REMOTE_PORT);
                                    if (rP != null && rP.length() != 0) {
                                        rauditx.addRelocateSection(107, rP);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added remote port: " + rP);
                                        }
                                    }

                                    String rH = (String)properties.get(AuditConstants.REMOTE_HOST);
                                    rH = truncateField(recordLengthExceeded, rH);
                                    if (rH != null && rH.length() != 0) {
                                        rauditx.addRelocateSection(108, rH);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added remote host: " + rH);
                                        }
                                    }

                                    String pN = (String)properties.get(AuditConstants.PROG_NAME);
                                    pN = truncateField(recordLengthExceeded, pN);
                                    if (pN != null && pN.length() != 0) {
                                        rauditx.addRelocateSection(110, pN);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added prog name: " + pN);
                                        }
                                    }

                                    String aN = (String)properties.get(AuditConstants.ACTION);
                                    aN = truncateField(recordLengthExceeded, aN);
                                    if (aN != null && aN.length() != 0) {
                                        rauditx.addRelocateSection(111, aN);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added action: " + aN);
                                        }
                                    }

                                    String rUN = (String)properties.get(AuditConstants.REGISTRY_USER_NAME);
                                    rUN = truncateField(recordLengthExceeded, rUN);
                                    if (rUN != null && rUN.length() != 0) {
                                        rauditx.addRelocateSection(112, rUN);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added reg user name: " + rUN);
                                        }
                                    }

                                    String aUN = (String)properties.get(AuditConstants.APP_USER_NAME);
                                    aUN = truncateField(recordLengthExceeded, aUN);
                                    if (aUN != null && aUN.length() != 0) {
                                        rauditx.addRelocateSection(113, aUN);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added app user name: " + aUN);
                                        }
                                    }

                                    String aD = (String)properties.get(AuditConstants.ACCESS_DECISION);
                                    aD = truncateField(recordLengthExceeded, aD);
                                    if (aD != null && aD.length() != 0) {
                                        rauditx.addRelocateSection(114, aD);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added access decison: " + aD);
                                        }
                                    }

                                    String nIA = (String)properties.get(AuditConstants.NAME_IN_APP);
                                    nIA = truncateField(recordLengthExceeded, nIA);
                                    if (nIA != null && nIA.length() != 0) {
                                        rauditx.addRelocateSection(115, nIA);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added name in app: " + nIA);
                                        }
                                    }

                                    String rT = (String)properties.get(AuditConstants.RESOURCE_TYPE);
                                    rT = truncateField(recordLengthExceeded, rT);
                                    if (rT != null && rT.length() != 0) {
                                        rauditx.addRelocateSection(116, rT);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added resource type: " + rT);
                                        }
                                    }

                                    Long rUID = (Long)properties.get(AuditConstants.RESOURCE_UNIQUE_ID);
                                    if (rUID != null) {
                                        rauditx.addRelocateSection(117, rUID.toString());
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added resource unique id: " + rUID);
                                        }
                                    }


                                    String[] permsChecked = (String[])properties.get(AuditConstants.PERMISSIONS_CHECKED);
                                    if (permsChecked != null && permsChecked.length != 0) {
                                        st = "";
                                        for (int i = 0; i < permsChecked.length; i++) {
                                            st = st.concat(permsChecked[i] + " , ");
                                        }
                                        if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);

                                        st = truncateField(recordLengthExceeded, st);
                                        rauditx.addRelocateSection(118, st);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added perms checked: " + st);
                                        }
                                    }

                                    String[] permsGranted = (String[])properties.get(AuditConstants.PERMISSIONS_GRANTED);
                                    if (permsGranted != null && permsGranted.length != 0) {
                                        st = "";
                                        for (int i = 0; i < permsGranted.length; i++) {
                                            st = st.concat(permsGranted[i] + " , ");
                                        }
                                        if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);
                                        st = truncateField(recordLengthExceeded, st);

                                        rauditx.addRelocateSection(119, st);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added perms granted: " + st);
                                        }
                                    }

                                    String[] rolesChecked = (String[])properties.get(AuditConstants.ROLES_CHECKED);
                                    if (rolesChecked != null && rolesChecked.length != 0) {
                                        st = "";
                                        for (int i = 0; i < rolesChecked.length; i++) {
                                            st = st.concat(rolesChecked[i] + " , ");
                                        }
                                        if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);
                                        st = truncateField(recordLengthExceeded, st);

                                        rauditx.addRelocateSection(120, st);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added roles checked: " + st);
                                        }
                                    }


                                    String[] rolesGranted = (String[])properties.get(AuditConstants.ROLES_GRANTED);
                                    if (rolesGranted != null && rolesGranted.length != 0) {
                                        st = "";
                                        for (int i = 0; i < rolesGranted.length; i++) {
                                            st = st.concat(rolesGranted[i] + " , ");
                                        }
                                        if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);
                                        st = truncateField(recordLengthExceeded, st);

                                        rauditx.addRelocateSection(121, st);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added roles granted: " + st);
                                        }
                                    }

                                    String fC = (String)properties.get(AuditConstants.FIRST_CALLER);
                                    fC = truncateField(recordLengthExceeded, fC);
                                    if (fC != null && fC.length() != 0) {
                                        rauditx.addRelocateSection(123, fC);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added first caller: " + fC);
                                        }
                                    }


                                    if (verbose) {
                                        String[] callerList = (String[])properties.get(AuditConstants.CALLER_LIST);
                                        if (callerList != null && callerList.length != 0) {
                                            st = "";
                                            for (int i = 0; i < callerList.length; i++) {
                                                st = st.concat(callerList[i] + " , ");
                                            }
                                            if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);

                                            st = truncateField(recordLengthExceeded, st);

                                            rauditx.addRelocateSection(124, st);
                                            if (tc.isDebugEnabled()) {
                                                Tr.debug(tc, "added callerList: " + st);
                                            }
                                        }
                                    }

                                    if (verbose) {
                                        String processD = (String)properties.get(AuditConstants.PROCESS_DOMAIN);
                                        processD = truncateField(recordLengthExceeded, processD);
                                        if (processD != null && processD.length() != 0) {
                                            rauditx.addRelocateSection(126, processD);
                                            if (tc.isDebugEnabled()) {
                                                Tr.debug(tc, "added process domain: " + processD);
                                            }
                                        }
                                    }

                                    String processR = (String)properties.get(AuditConstants.PROCESS_REALM);
                                    processR = truncateField(recordLengthExceeded, processR);
                                    if (processR != null && processR.length() != 0) {
                                        rauditx.addRelocateSection(127, processR);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added process realm: " + processR);
                                        }
                                    }

                                    String registryT = (String)properties.get(AuditConstants.REGISTRY_TYPE);
                                    registryT = truncateField(recordLengthExceeded, registryT);
                                    if (registryT != null && registryT.length() != 0) {
                                        rauditx.addRelocateSection(129, registryT);
                                        if (tc.isDebugEnabled()) {
                                            Tr.debug(tc, "added registryType: " + registryT);
                                        }
                                    }


                                    // Now, based on the event being captures, we may have other pieces of audit data to
                                    // populate as well.  It is based on:
                                    // Event Type	                Context Objects
                                    // SECURITY_AUTHN	                authnContext, providerContext
                                    // SECURITY_AUTHN_CREDS_MODIFY	
                                    // SECURITY_AUTHN_DELEGATION	delegationContext
                                    // SECURITY_AUTHN_MAPPING	        authnMapping, providerContext
                                    // SECURITY_AUTHN_TERMINATE	        authnContext, providerContext, authnTermContext
                                    // SECURITY_AUTHZ	                providerContext, policyContext
                                    // SECURITY_ENCRYPTION	        keyContext
                                    // SECURITY_MGMT_AUDIT	        mgmtContext
                                    // SECURITY_MGMT_CONFIG	        mgmtContext,
                                    // SECURITY_MGMT_KEY	        mgmtContext, keyContext
                                    // SECURITY_MGMT_POLICY	        mgmtContext, policyContext
                                    // SECURITY_MGMT_PROVISIONING	mgmtContext, regObjContext
                                    // SECURITY_MGMT_REGISTRY	        mgmtContext, regObjContext
                                    // SECURITY_MGMT_RESOURCE           mgmtContext
                                    // SECURITY_RESOURCE_ACCESS         responseContext
                                    // SECURITY_RUNTIME	
                                    // SECURITY_RUNTIME_KEY             keyContext
                                    // SECURITY_SIGNING	                keyContext

                                    // Check if we should gather the delegation information. This should only
                                    // be in the case that we have a SECURITY_AUTH_DELEGATION event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHN_DELEGATION_CODE) {

                                        String delStr = (String)properties.get(AuditConstants.DELEGATION_TYPE);
                                        delStr = truncateField(recordLengthExceeded, delStr);
                                        if (delStr != null && delStr.length() != 0) {
                                            rauditx.addRelocateSection(131, delStr);
                                        }

                                        delStr = (String)properties.get(AuditConstants.ROLE_NAME);
                                        delStr = truncateField(recordLengthExceeded, delStr);
                                        if (delStr != null && delStr.length() != 0) {
                                            rauditx.addRelocateSection(132, delStr);
                                        }

                                        delStr = (String)properties.get(AuditConstants.IDENTITY_NAME);
                                        delStr = truncateField(recordLengthExceeded, delStr);
                                        if (delStr != null && delStr.length() != 0) {
                                            rauditx.addRelocateSection(133, delStr);
                                        }
                                    }

                                    // Check if we should gather the authentication information.  This should only
                                    // be in the case that we have either a SECURITY_AUTHN or SECURITY_AUTHN_TERMNATE event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHN_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_AUTHN_TERMINATE_CODE) {
                                        String authT = (String)properties.get(AuditConstants.AUTHN_TYPE);
                                        authT = truncateField(recordLengthExceeded, authT);
                                        if (authT != null && authT.length() != 0) {
                                            rauditx.addRelocateSection(135, authT);
                                        }
                                    }

                                    // Check if we should gather the provider information.  This should only be
                                    // in the case that we have a SECURITY_AUTHN, SECURITY_AUTHN_MAPPING, SECURITY_AUTHN_TERMINATE,
                                    // or SECURITY_AUTHZ event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHN_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_AUTHN_TERMINATE_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_AUTHN_MAPPING_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_AUTHZ_CODE) {

                                        String providerStr = (String)properties.get(AuditConstants.PROVIDER);  
                                        providerStr = truncateField(recordLengthExceeded, providerStr);
                                        if (providerStr != null && providerStr.length() != 0) {
                                            rauditx.addRelocateSection(137, providerStr);
                                        }

                                        providerStr = (String)properties.get(AuditConstants.PROVIDER_STATUS);
                                        providerStr = truncateField(recordLengthExceeded, providerStr);
                                        if (providerStr != null && providerStr.length() != 0) {
                                            rauditx.addRelocateSection(138, providerStr);
                                        }

                                    }

                                    // Check if we should gather the authentication mapping information.  This should only be in
                                    // the case that we have a SECURITY_AUTHN_MAPPING type of event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHN_MAPPING_CODE) {

                                        String mapStr = (String)properties.get(AuditConstants.MAPPED_SECURITY_DOMAIN);
                                        mapStr = truncateField(recordLengthExceeded, mapStr);
                                        if (mapStr != null && mapStr.length() != 0) {
                                            rauditx.addRelocateSection(140, mapStr);
                                        }

                                        mapStr = (String)properties.get(AuditConstants.MAPPED_REALM);
                                        mapStr = truncateField(recordLengthExceeded, mapStr);
                                        if (mapStr != null && mapStr.length() != 0) {
                                            rauditx.addRelocateSection(141, mapStr);
                                        }

                                        mapStr = (String)properties.get(AuditConstants.MAPPED_USER_NAME);
                                        mapStr = truncateField(recordLengthExceeded, mapStr);
                                        if (mapStr != null && mapStr.length() != 0) {
                                            rauditx.addRelocateSection(142, mapStr);
                                        }
                                    }

                                    // Check if we should gather the authentication termination information. This should only be in
                                    // the case that we have a SECURITY_AUTHN_TERMINATE type of event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHN_TERMINATE_CODE) {

                                        String termR = (String)properties.get(AuditConstants.TERMINATE_REASON);
                                        termR = truncateField(recordLengthExceeded, termR);
                                        if (termR != null && termR.length() != 0) {
                                            rauditx.addRelocateSection(144, termR);
                                        }
                                    }

                                    // Check if we should gather the policy information.  This should only be in the case 
                                    // that we have a SECURITY_AUTHZ or SECURITY_MGMT_POLICY type of event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_AUTHZ_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_POLICY_CODE) {

                                        String policyStr = (String)properties.get(AuditConstants.POLICY_NAME);
                                        policyStr = truncateField(recordLengthExceeded, policyStr);
                                        if (policyStr != null && policyStr.length() != 0) {
                                            rauditx.addRelocateSection(146, policyStr);
                                        }

                                        policyStr = (String)properties.get(AuditConstants.POLICY_TYPE);
                                        policyStr = truncateField(recordLengthExceeded, policyStr);
                                        if (policyStr != null && policyStr.length() != 0) {
                                            rauditx.addRelocateSection(147, policyStr);
                                        }
                                    }

                                    // Check if we should gather the key information.  This should only be in the case that we
                                    // have a SECURITY_ENCRYPTION, SECURITY_MGMT_KEY, SECURITY_RUNTIME_KEY, or SECURITY_SIGNING
                                    // type of event

                                    if (auditEventType == AuditConstants.SMF_SECURITY_ENCRYPTION_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_KEY_CODE ||
                                        auditEventType == AuditConstants.SMF_SECURITY_RUNTIME_KEY_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_SIGNING_CODE) {

                                        String keyStr = (String)properties.get(AuditConstants.KEY_LABEL);
                                        keyStr = truncateField(recordLengthExceeded, keyStr);
                                        if (keyStr != null && keyStr.length() != 0) {
                                            rauditx.addRelocateSection(149, keyStr);
                                        }

                                        keyStr = (String)properties.get(AuditConstants.KEY_LOCATION);
                                        keyStr = truncateField(recordLengthExceeded, keyStr);
                                        if (keyStr != null && keyStr.length() != 0) {
                                            rauditx.addRelocateSection(150, keyStr);
                                        }

                                        Date d = (Date)properties.get(AuditConstants.CERT_LIFETIME);
                                        if (d != null) {
                                            rauditx.addRelocateSection(151, d.toString());
                                        }
                                    }

                                    // Check if we should gather the management information.  This should only be in the case of 
                                    // any of the SECURITY_MGMT_XXX events

                                    if (auditEventType == AuditConstants.SMF_SECURITY_MGMT_AUDIT_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_CONFIG_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_KEY_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_POLICY_CODE ||
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_PROVISIONING_CODE || 
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_REGISTRY_CODE ||
                                        auditEventType == AuditConstants.SMF_SECURITY_MGMT_RESOURCE_CODE) {

                                        String mgmtStr = (String)properties.get(AuditConstants.MGMT_TYPE);
                                        mgmtStr = truncateField(recordLengthExceeded, mgmtStr);
                                        if (mgmtStr != null && mgmtStr.length() != 0) {
                                            rauditx.addRelocateSection(153, mgmtStr);
                                        }

                                        mgmtStr = (String)properties.get(AuditConstants.MGMT_COMMAND);
                                        mgmtStr = truncateField(recordLengthExceeded, mgmtStr);
                                        if (mgmtStr != null && mgmtStr.length() != 0) {
                                            rauditx.addRelocateSection(154, mgmtStr);
                                        }

                                        if (verbose) {
                                            TargetAttributes[] ta = (TargetAttributes[])properties.get(AuditConstants.TARGET_INFO_ATTRIBUTES);
                                            if (ta != null && ta.length != 0) {
                                                st = "";
                                                for (int i = 0; i < ta.length; i++) {
                                                    st = st.concat("MgmtAttrName = " + ta[i].getName() + " , ");
                                                    st = st.concat("MgmtAttrUid = " + ta[i].getUniqueId() + " , ");
                                                }
                                            }
                                            if (st.endsWith(" , ")) st = st.substring(0, st.length() - 3);
                                            st = truncateField(recordLengthExceeded, st);
                                            rauditx.addRelocateSection(155, st);
                                        }
                                    }

                                    // Check if we should gather the response information. This should only be for the 
                                    // SECURITY_RESOURCE_ACCESS event type

                                    if (auditEventType == AuditConstants.SMF_SECURITY_RESOURCE_ACCESS_CODE) {
                                        String urlStr = (String)properties.get(AuditConstants.URL);
                                        urlStr = truncateField(recordLengthExceeded, urlStr);
                                        if (urlStr != null & urlStr.length() != 0) {
                                            rauditx.addRelocateSection(157, urlStr);
                                            if (tc.isDebugEnabled()) {
                                                Tr.debug(tc, "added urlStr: " + urlStr);
                                            }
                                        }

                                        if (verbose && !recordLengthExceeded) {
                                            Attributes[] httpRequestHeaders = (Attributes[])properties.get(AuditConstants.HTTP_REQUEST_HEADERS);
                                            Attributes[] httpResponseHeaders = (Attributes[])properties.get(AuditConstants.HTTP_RESPONSE_HEADERS);
                                            processHTTPRequestHeaders(httpRequestHeaders);
                                            processHTTPResponseHeaders(httpResponseHeaders);
                                        }
                                    }

                                    // Handle any custom data for this event

                                    String[] customKeys = sae.getCustomKeys();
                                    String[] customValues = sae.getCustomValues();

                                    if (customKeys != null && customKeys.length != 0 && !recordLengthExceeded) {
                                        st = "";
                                        if (customKeys[0] != null) {
                                            for (int i = 0; i < customKeys.length; i++) {
                                                st = st.concat("customKey: " + customKeys[i]);
                                                st = st.concat(" customVal: " + customValues[i] + ", ");
                                            }
                                            if (st.endsWith(", ")) st = st.substring(0, st.length() - 2);
                                            rauditx.addRelocateSection(161, st);
                                        }
                                    }


                                    // set the event sequence number
                                    Integer seqNum = (Integer)properties.get(AuditConstants.SEQUENCE_NUMBER);
                                    rauditx.addRelocateSection(162, seqNum.toString());
                                    if (tc.isDebugEnabled()) {
                                        Tr.debug(tc, "added seq num: " + seqNum.toString());
                                    }

                                    // set the outcome reason
                                    String outcomeReason = (String)properties.get(AuditConstants.OUTCOME_FAILURE_REASON);
                                    rauditx.addRelocateSection(163, outcomeReason); 
                                    if (tc.isDebugEnabled()) {
                                        Tr.debug(tc, "added outcome reason: " + outcomeReason);
                                    }

                                    // set the outcome reason code
                                    Long outcomeReasonCode = (Long)properties.get(AuditConstants.OUTCOME_REASON);
                                    rauditx.addRelocateSection(164, outcomeReasonCode.toString());
                                    if (tc.isDebugEnabled()) {
                                        Tr.debug(tc, "added outcomeReasonCode: " + outcomeReasonCode.toString());
                                    }

                			*/	
                				// - end fill in data


                				// set component name
                				rauditx.setComponent("WASAUDITCOMP");

                				// Send our rauditx record along for SMF processing

                				if (tc.isDebugEnabled())
                					Tr.debug(tc, "beforeRAUDITXISSUE");
/*                				if (tc.isDebugEnabled()) {
                					Tr.debug(tc, "length of eventBytes: " + eventBytes.length);
                					if (recordLengthExceeded) {
                						Tr.debug(tc, "fields were truncated to a size limit of: " + fieldLengthLimit);
                					}
                				}
*/                				
                				rauditx.issue();
                				if (tc.isDebugEnabled())
                					Tr.debug(tc, "afterRAUDITXISSUE");

                				if (tc.isDebugEnabled()) Tr.debug(tc, "Rauditx_issued");

                			} catch (InvocationTargetException te) {
                				Throwable cause = te.getCause();
                				if (tc.isDebugEnabled()) {
                					Tr.debug(tc, "Exception writing to Rauditx: " +  te.getMessage());
                					if (cause != null)
                						Tr.debug(tc, " cause " + cause.getMessage());
                					Tr.debug(tc, " target exception: " + te.getTargetException());
                					te.printStackTrace();
                				}

                				throw new Exception(te.getMessage());
                			} catch (Exception ee) {
                				if (tc.isDebugEnabled()) {
                					Tr.debug(tc, "Exception writing to Rauditx, getMessage: " +  ee.getMessage());
                					Tr.debug(tc, "exception cause: " + ee.getCause().toString());
                					Tr.debug(tc, "exception stacktrace: " + ee.getStackTrace());
                					Tr.debug(tc, "exceptions suppressed: " + ee.getSuppressed().toString());

                				}

                				throw new Exception(ee.getMessage());
                            }
                		}

                		//auditLog.writeRecord(mapToJSONString(event.getMap()));
                    }

                }
            } catch (Exception e) {

            }
        }
    }


    /**
     * Method to enable unit testing (setting for mocks)
     */
    void set_rauditx(RAuditxWrapper rauditx)
    {
        this.rauditx = rauditx;
    }



    /**
     * <p>
     * The <code>truncateField</code> method returns a truncated field if the size of the audit record
     * exceeds the maximum SMF boundary.  The truncation size is based on either a custom property 
     * defined on the service provider and referenced by com.ibm.audit.field.length.limit, or defaults to
     * 128.
     *
     **/
    public String truncateField(boolean recordLengthExceeded, String str) {
        if (tc.isDebugEnabled()) {
            Tr.entry(tc, "truncateField: recordLengthExceeded = " + recordLengthExceeded + " str = " + str);
        }
        if (str != null) {
            if (recordLengthExceeded && str.length() > fieldLengthLimit) {
                str = str.substring(0, fieldLengthLimit - 1);
            }
        }
        if (tc.isDebugEnabled()) {
            Tr.exit(tc, "truncateField: recordLengthExceeded = " + recordLengthExceeded + " str = " + str);
        }
        return str;
    }


}
