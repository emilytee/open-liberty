/*******************************************************************************
 * Copyright (c) 2017 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

package jpa10callback.listeners.orderofinvocation.a1;

import javax.persistence.PostLoad;
import javax.persistence.PostPersist;
import javax.persistence.PostRemove;
import javax.persistence.PostUpdate;
import javax.persistence.PrePersist;
import javax.persistence.PreRemove;
import javax.persistence.PreUpdate;

import jpa10callback.AbstractCallbackListener;

public class AnoCallbackListenerPublicA1 extends AbstractCallbackListener {
    private static final AnoCallbackListenerPublicA1 _singleton = new AnoCallbackListenerPublicA1();

    public final static AbstractCallbackListener getSingleton() {
        return _singleton;
    }

    public final static void reset() {
        _singleton.resetCallbackData();
    }

    @PrePersist
    public void prePersistCallback(Object entity) {
        _singleton.doPrePersist(ProtectionType.PT_PUBLIC);
    }

    @PostPersist
    public void postPersistCallback(Object entity) {
        _singleton.doPostPersist(ProtectionType.PT_PUBLIC);
    }

    @PreUpdate
    public void preUpdateCallback(Object entity) {
        _singleton.doPreUpdate(ProtectionType.PT_PUBLIC);
    }

    @PostUpdate
    public void postUpdateCallback(Object entity) {
        _singleton.doPostUpdate(ProtectionType.PT_PUBLIC);
    }

    @PreRemove
    public void preRemoveCallback(Object entity) {
        _singleton.doPreRemove(ProtectionType.PT_PUBLIC);
    }

    @PostRemove
    public void postRemoveCallback(Object entity) {
        _singleton.doPostRemove(ProtectionType.PT_PUBLIC);
    }

    @PostLoad
    public void postLoadCallback(Object entity) {
        _singleton.doPostLoad(ProtectionType.PT_PUBLIC);
    }
}