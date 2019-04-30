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

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import com.ibm.ejs.ras.Tr;
import com.ibm.ejs.ras.TraceComponent;

public class RAuditxWrapper {


    private final static TraceComponent tc = Tr.register(RAuditxWrapper.class);
	private Class<?> Rauditx = null;
    private Object rauditxInstance = null;

    public RAuditxWrapper()
    {
    	try {            		
    		Rauditx = Class.forName("com.ibm.jzos.Rauditx");
    		rauditxInstance = Rauditx.newInstance();

    	} catch (ClassNotFoundException ex) {
    		if (tc.isDebugEnabled()) {
    			Tr.debug(tc, "Could not find call com.ibm.ws.jzos.Rauditx, re-attempting with ExtClassLoader");
    		}
    		com.ibm.ws.ffdc.FFDCFilter.processException(ex, "com.ibm.ws.security.audit.zOS.RAuditxWrapper.ctor", "49", this);
    	} catch (Exception e) {
    		if (tc.isDebugEnabled()) {
    			Tr.debug(tc, "Exception caught: " + e.getMessage());
    		}
    		com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.zOS.RauditxWrapper.ctor", "55", this);
    	}
    	/*
    	try {
    		if (Rauditx == null) { 
    			Rauditx = Class.forName("com.ibm.jzos.Rauditx", true, ExtClassLoader.getInstance());  
    			rauditxInstance = Rauditx.newInstance();
    		}
    	} catch (ClassNotFoundException ex) {
    		if (tc.isDebugEnabled()) {
    			Tr.debug(tc, "Could not find call comm.ibm.ws.jzos.Rauditx with ExtClassLoader");
    		}
    		com.ibm.ws.ffdc.FFDCFilter.processException(ex, "com.ibm.ws.security.audit.zOS.RauditxWrapper.ctor", "66", this);

    	} catch (Exception e) {

    		if (tc.isDebugEnabled()) {
    			Tr.debug(tc, "Exception caught: " + e.getMessage());
    		}
    		com.ibm.ws.ffdc.FFDCFilter.processException(e, "com.ibm.ws.security.audit.zOS.RauditxWrapper.ctor", "73", this);
    	}
    	*/
    }

    public void setEventSuccess()
    		throws PrivilegedActionException, InvocationTargetException
    {
    	rauditxReflect(Rauditx, rauditxInstance, "setEventSuccess", null, null);
    }

    public void setEventFailure()
    		throws PrivilegedActionException, InvocationTargetException
    {
    	rauditxReflect(Rauditx, rauditxInstance, "setEventFailure", null, null);
    }

    public void setQualifier(int qualifer)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {int.class};
    	Object[] argValues = new Object[] {new Integer(qualifer)};
    	rauditxReflect(Rauditx, rauditxInstance, "setQualifier", argTypes, argValues);
    }

    public void setEvent(int event)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {int.class};
    	Object[] argValues = new Object[] {new Integer(event)};
    	rauditxReflect(Rauditx, rauditxInstance, "setEvent", argTypes, argValues);
    }

    public void setSubtype(int subtype)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {int.class};
    	Object[] argValues = new Object[] {new Integer(subtype)};
    	rauditxReflect(Rauditx, rauditxInstance, "setSubtype", argTypes, argValues); 
    }

    public void setFmid(String fmid)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {String.class};
    	Object[] argValues = new Object[] {new String(fmid)};
    	rauditxReflect(Rauditx, rauditxInstance, "setFmid", argTypes, argValues);
    }

    public void setAlwaysLogSuccesses()
    		throws PrivilegedActionException, InvocationTargetException
    {
    	rauditxReflect(Rauditx, rauditxInstance, "setAlwaysLogSuccesses", null, null);
    }

    public void setAlwaysLogFailures()
    		throws PrivilegedActionException, InvocationTargetException
    {
    	rauditxReflect(Rauditx, rauditxInstance, "setAlwaysLogFailures", null, null);
    }

    public void addRelocateSection(int type, String data)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {int.class, String.class};
    	Object[] argValues = new Object[] {new Integer(type), new String(data)};
    	rauditxReflect(Rauditx, rauditxInstance, "addRelocateSection", argTypes, argValues);
    }

    public void setComponent(final String component)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	Class<?>[] argTypes = new Class[] {String.class};
    	Object[] argValues = new Object[] {new String(component)};
    	rauditxReflect(Rauditx, rauditxInstance, "setComponent", argTypes, argValues);
    }

    public void issue()                                                         
    		throws PrivilegedActionException, InvocationTargetException
    {
    	rauditxReflect(Rauditx, rauditxInstance, "issue", null, null);
    }

    private Object rauditxReflect(final Class<?> classIn, final Object rauditxInstance, final String MethodName, final Class<?> [] argsType, final Object[] argsValue)
    		throws PrivilegedActionException, InvocationTargetException
    {
    	if ( argsValue == null) {
    		return AccessController.doPrivileged(
    				new PrivilegedExceptionAction<String>() {
    					public String run() throws Exception {							 
    						Method myMethod = classIn.getMethod(MethodName, new Class<?>[] {});
    						return (String) myMethod.invoke(rauditxInstance, new Object [] {});
    					}
    				}
    				);
		} else {
			return AccessController.doPrivileged(
					new PrivilegedExceptionAction<String>() {
						public String run() throws Exception {	
							Method myMethod = classIn.getMethod(MethodName, argsType);
							return (String) myMethod.invoke(rauditxInstance, argsValue);
						}
					}
					);
		} 
    	
	}
}