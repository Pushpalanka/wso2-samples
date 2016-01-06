package org.wso2.carbon.identity.custom.claim.handler;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.claim.mgt.ClaimManagementException;
import org.wso2.carbon.claim.mgt.ClaimManagerHandler;
import org.wso2.carbon.core.util.AnonymousSessionUtil;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.claims.impl.DefaultClaimHandler;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.user.api.ClaimManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserRealm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * ClaimHandler written fixing https://wso2.org/jira/browse/IDENTITY-4250
 * to return user claims in openid connect scenario
 */
public class CustomClaimHandler extends DefaultClaimHandler {

    private static final Log log = LogFactory.getLog(CustomClaimHandler.class);

    @Override
    protected Map<String, String> handleLocalClaims(String spStandardDialect,
                                                    StepConfig stepConfig,
                                                    AuthenticationContext context) throws FrameworkException {


        ApplicationConfig appConfig = context.getSequenceConfig().getApplicationConfig();
        ServiceProvider serviceProvider = appConfig.getServiceProvider();
        ClaimConfig claimConfig = serviceProvider.getClaimConfig();
        boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();

        Map<String, String> spToLocalClaimMappings = appConfig.getClaimMappings();
        if (spToLocalClaimMappings == null) {
            spToLocalClaimMappings = new HashMap<>();
        }

        Map<String, String> carbonToStandardClaimMapping = new HashMap<>();
        Map<String, String> requestedClaimMappings = appConfig.getRequestedClaimMappings();
        if (requestedClaimMappings == null) {
            requestedClaimMappings = new HashMap<>();
        }

        AuthenticatedUser authenticatedUser = getAuthenticatedUser(stepConfig, context);

        String tenantDomain = authenticatedUser.getTenantDomain();
        String tenantAwareUserName = authenticatedUser.getUserName();

        UserRealm realm = getUserRealm(tenantDomain);

        if (realm == null) {
            log.warn("No valid tenant domain provider. No claims returned back");
            return new HashMap<>();
        }

        ClaimManager claimManager = getClaimManager(tenantDomain, realm);

        UserStoreManager userStore = getUserStoreManager(tenantDomain, realm, authenticatedUser.getUserStoreDomain());

        // key:value -> carbon_dialect:claim_value
        Map<String, String> allLocalClaims;

        // If default dialect -> all non-null user claims
        // If custom dialect -> all non-null user claims that have been mapped to custom claims
        // key:value -> sp_dialect:claim_value
        Map<String, String> allSPMappedClaims = new HashMap<>();

        // Requested claims only
        // key:value -> sp_dialect:claim_value
        Map<String, String> spRequestedClaims = new HashMap<>();

        // Retrieve all non-null user claim values against local claim uris.
        allLocalClaims = retrieveAllNunNullUserClaimValues(authenticatedUser, tenantDomain, tenantAwareUserName,
                claimManager, userStore);

        context.setProperty(FrameworkConstants.UNFILTERED_LOCAL_CLAIM_VALUES, allLocalClaims);

        if (StringUtils.isNotBlank(spStandardDialect) && !StringUtils.equals(spStandardDialect, ApplicationConstants
                .LOCAL_IDP_DEFAULT_CLAIM_DIALECT)) {
            requestedClaimMappings = getStanderDialectToCarbonMapping(spStandardDialect, context,
                    requestedClaimMappings, context.getTenantDomain());
        }

        // if standard dialect get all claim mappings from standard dialect to carbon dialect
        spToLocalClaimMappings = getStanderDialectToCarbonMapping(spStandardDialect, context, spToLocalClaimMappings,
                tenantDomain);

        if (!isLocalClaimDialect && StringUtils.isNotBlank(spStandardDialect)) {
            carbonToStandardClaimMapping = getCarbonToStandardDialectMapping(spStandardDialect, context,
                    spToLocalClaimMappings, tenantDomain);
            requestedClaimMappings = mapRequestClaimsInStandardDialect(requestedClaimMappings,
                    carbonToStandardClaimMapping);
        }

        mapSPClaimsAndFilterRequestedClaims(spToLocalClaimMappings, requestedClaimMappings, allLocalClaims,
                allSPMappedClaims, spRequestedClaims);

        context.setProperty(FrameworkConstants.UNFILTERED_SP_CLAIM_VALUES, allSPMappedClaims);

        if (spStandardDialect != null) {
            setSubjectClaimForLocalClaims(tenantAwareUserName, userStore,
                    allLocalClaims, spStandardDialect, context);
        } else {
            setSubjectClaimForLocalClaims(tenantAwareUserName, userStore,
                    allSPMappedClaims, null, context);
        }


        if (FrameworkConstants.RequestType.CLAIM_TYPE_OPENID.equals(context.getRequestType())) {
            spRequestedClaims = allSPMappedClaims;
        }

        /*
        * This is a custom change added to pass 'MultipleAttributeSeparator' attribute value to other components,
        * since we can't get the logged in user in some situations.
        *
        * Following components affected from this change -
        * org.wso2.carbon.identity.application.authentication.endpoint
        * org.wso2.carbon.identity.provider
        * org.wso2.carbon.identity.oauth
        * org.wso2.carbon.identity.oauth.endpoint
        * org.wso2.carbon.identity.sso.saml
        *
        * TODO: Should use Map<String, List<String>> in future for claim mapping
        * */
        addMultiAttributeSperatorToRequestedClaims(authenticatedUser, (org.wso2.carbon.user.core.UserStoreManager)
                userStore, spRequestedClaims);

        return spRequestedClaims;
    }

    private AuthenticatedUser getAuthenticatedUser(StepConfig stepConfig, AuthenticationContext context) {
        AuthenticatedUser authenticatedUser;
        if(stepConfig != null) {
            authenticatedUser = stepConfig.getAuthenticatedUser();
        } else {
            authenticatedUser = context.getSequenceConfig().getAuthenticatedUser();
        }

        return authenticatedUser;
    }

    private UserRealm getUserRealm(String tenantDomain) throws FrameworkException {
        try {
            UserRealm realm = AnonymousSessionUtil.getRealmByTenantDomain(FrameworkServiceComponent.getRegistryService(), FrameworkServiceComponent.getRealmService(), tenantDomain);
            return realm;
        } catch (CarbonException var4) {
            throw new FrameworkException("Error occurred while retrieving the Realm for " + tenantDomain + " to handle local claims", var4);
        }
    }

    private ClaimManager getClaimManager(String tenantDomain, UserRealm realm) throws FrameworkException {
        org.wso2.carbon.user.core.claim.ClaimManager claimManager = null;

        try {
            claimManager = realm.getClaimManager();
            return claimManager;
        } catch (UserStoreException var5) {
            throw new FrameworkException("Error occurred while retrieving the ClaimManager from Realm for " + tenantDomain + " to handle local claims", var5);
        }
    }

    private UserStoreManager getUserStoreManager(String tenantDomain, UserRealm realm, String userDomain) throws FrameworkException {
        org.wso2.carbon.user.core.UserStoreManager userStore = null;

        try {
            userStore = realm.getUserStoreManager();
            if(StringUtils.isNotBlank(userDomain)) {
                userStore = realm.getUserStoreManager().getSecondaryUserStoreManager(userDomain);
            }

            if(userStore == null) {
                throw new FrameworkException("Invalid user store domain name : " + userDomain + " in tenant : " + tenantDomain);
            } else {
                return userStore;
            }
        } catch (UserStoreException var6) {
            throw new FrameworkException("Error occurred while retrieving the UserStoreManager from Realm for " + tenantDomain + " to handle local claims", var6);
        }
    }


    private Map<String, String> getStanderDialectToCarbonMapping(String spStandardDialect, AuthenticationContext context, Map<String, String> spToLocalClaimMappings, String tenantDomain) throws FrameworkException {
        if(spStandardDialect != null) {
            try {
                spToLocalClaimMappings = this.getClaimMappings(spStandardDialect, (Set)null, context.getTenantDomain(), false);
            } catch (Exception var6) {
                throw new FrameworkException("Error occurred while getting all claim mappings from " + spStandardDialect + " dialect to " + "http://wso2.org/claims" + " dialect for " + tenantDomain + " to handle local claims", var6);
            }
        }

        return spToLocalClaimMappings;
    }

    private Map<String, String> getCarbonToStandardDialectMapping(String spStandardDialect, AuthenticationContext context, Map<String, String> spToLocalClaimMappings, String tenantDomain) throws FrameworkException {
        if(spStandardDialect != null) {
            try {
                spToLocalClaimMappings = this.getClaimMappings(spStandardDialect, (Set)null, context.getTenantDomain(), true);
            } catch (Exception var6) {
                throw new FrameworkException("Error occurred while getting all claim mappings from http://wso2.org/claims dialect to " + spStandardDialect + " dialect for " + tenantDomain + " to handle local claims", var6);
            }
        }

        return spToLocalClaimMappings;
    }

    private Map<String, String> retrieveAllNunNullUserClaimValues(AuthenticatedUser authenticatedUser, String tenantDomain, String tenantAwareUserName, ClaimManager claimManager, UserStoreManager userStore) throws FrameworkException {
        Object allLocalClaims = new HashMap();

        try {
            org.wso2.carbon.user.api.ClaimMapping[] e = claimManager.getAllClaimMappings("http://wso2.org/claims");
            ArrayList localClaimURIs = new ArrayList();
            org.wso2.carbon.user.api.ClaimMapping[] arr$ = e;
            int len$ = e.length;

            for(int i$ = 0; i$ < len$; ++i$) {
                org.wso2.carbon.user.api.ClaimMapping mapping = arr$[i$];
                String claimURI = mapping.getClaim().getClaimUri();
                localClaimURIs.add(claimURI);
            }

            allLocalClaims = userStore.getUserClaimValues(tenantAwareUserName, (String[])localClaimURIs.toArray(new String[localClaimURIs.size()]), (String)null);
        } catch (UserStoreException var14) {
            if(!var14.getMessage().contains("UserNotFound")) {
                throw new FrameworkException("Error occurred while getting all user claims for " + authenticatedUser + " in " + tenantDomain, var14);
            }

            if(log.isDebugEnabled()) {
                log.debug("User " + tenantAwareUserName + " not found in user store");
            }
        }

        if(allLocalClaims == null) {
            allLocalClaims = new HashMap();
        }

        return (Map)allLocalClaims;
    }


    private Map<String, String> getClaimMappings(String otherDialect, Set<String> keySet, String tenantDomain, boolean useLocalDialectAsKey) throws FrameworkException {
        Object claimMapping = null;

        try {
            claimMapping = ClaimManagerHandler.getInstance().getMappingsMapFromOtherDialectToCarbon(otherDialect, keySet, tenantDomain, useLocalDialectAsKey);
        } catch (ClaimManagementException var7) {
            throw new FrameworkException("Error while loading mappings.", var7);
        }

        if(claimMapping == null) {
            claimMapping = new HashMap();
        }

        return (Map)claimMapping;
    }


    private Map<String, String> mapRequestClaimsInStandardDialect(Map<String, String> requestedClaimMappings, Map<String, String> carbonToStandardClaimMapping) {
        HashMap requestedClaimMappingsInStandardDialect = new HashMap();
        if(requestedClaimMappings != null) {
            Iterator iterator = requestedClaimMappings.entrySet().iterator();

            while(iterator.hasNext()) {
                Map.Entry mapping = (Map.Entry)iterator.next();
                String standardMappedClaim = (String)carbonToStandardClaimMapping.get(mapping.getValue());
                if(StringUtils.isNotBlank(standardMappedClaim)) {
                    requestedClaimMappingsInStandardDialect.put(standardMappedClaim, mapping.getValue());
                }
            }
        }

        return requestedClaimMappingsInStandardDialect;
    }

    private void mapSPClaimsAndFilterRequestedClaims(Map<String, String> spToLocalClaimMappings, Map<String, String> requestedClaimMappings, Map<String, String> allLocalClaims, Map<String, String> allSPMappedClaims, Map<String, String> spRequestedClaims) {
        Iterator i$ = spToLocalClaimMappings.entrySet().iterator();

        while(i$.hasNext()) {
            Map.Entry entry = (Map.Entry)i$.next();
            String spClaimURI = (String)entry.getKey();
            String localClaimURI = (String)entry.getValue();
            String claimValue = (String)allLocalClaims.get(localClaimURI);
            if(claimValue != null) {
                allSPMappedClaims.put(spClaimURI, claimValue);
                if(requestedClaimMappings.get(spClaimURI) != null) {
                    spRequestedClaims.put(spClaimURI, claimValue);
                }
            }
        }

    }

    private void setSubjectClaimForLocalClaims(String tenantAwareUserId, UserStoreManager userStore, Map<String, String> attributesMap, String spStandardDialect, AuthenticationContext context) {
        String subjectURI = context.getSequenceConfig().getApplicationConfig().getSubjectClaimUri();
        if(subjectURI != null && !subjectURI.isEmpty()) {
            if(spStandardDialect != null) {
                this.setSubjectClaim(tenantAwareUserId, userStore, attributesMap, spStandardDialect, context);
                if(context.getProperty("ServiceProviderSubjectClaimValue") == null) {
                    log.warn("Subject claim could not be found amongst unfiltered local claims");
                }
            } else {
                this.setSubjectClaim(tenantAwareUserId, userStore, attributesMap, (String)null, context);
                if(context.getProperty("ServiceProviderSubjectClaimValue") == null) {
                    log.warn("Subject claim could not be found amongst service provider mapped unfiltered local claims");
                }
            }
        }

    }


    private void setSubjectClaim(String tenantAwareUserId, UserStoreManager userStore, Map<String, String> attributesMap, String spStandardDialect, AuthenticationContext context) {
        String subjectURI = context.getSequenceConfig().getApplicationConfig().getSubjectClaimUri();
        ApplicationConfig applicationConfig = context.getSequenceConfig().getApplicationConfig();
        ServiceProvider serviceProvider = applicationConfig.getServiceProvider();
        ClaimConfig claimConfig = serviceProvider.getClaimConfig();
        boolean isLocalClaimDialect = claimConfig.isLocalClaimDialect();
        Map spToLocalClaimMappings = applicationConfig.getClaimMappings();
        if(subjectURI != null) {
            if(!isLocalClaimDialect && spStandardDialect != null && spToLocalClaimMappings != null) {
                subjectURI = (String)spToLocalClaimMappings.get(subjectURI);
            }

            if(attributesMap.get(subjectURI) != null) {
                context.setProperty("ServiceProviderSubjectClaimValue", attributesMap.get(subjectURI));
                if(log.isDebugEnabled()) {
                    log.debug("Setting \'ServiceProviderSubjectClaimValue\' property value from attribute map " + (String)attributesMap.get(subjectURI));
                }
            } else {
                log.debug("Subject claim not found among attributes");
            }

            if(tenantAwareUserId == null || userStore == null) {
                log.debug("Tenant aware username or user store \'NULL\'. Possibly federated case");
                return;
            }

            if(spStandardDialect != null) {
                this.setSubjectClaimForStandardDialect(tenantAwareUserId, userStore, context, subjectURI);
            }
        }

    }

    private void setSubjectClaimForStandardDialect(String tenantAwareUserId, UserStoreManager userStore, AuthenticationContext context, String subjectURI) {
        try {
            String e = userStore.getUserClaimValue(tenantAwareUserId, subjectURI, (String)null);
            if(e != null) {
                context.setProperty("ServiceProviderSubjectClaimValue", e);
                if(log.isDebugEnabled()) {
                    log.debug("Setting \'ServiceProviderSubjectClaimValue\' property value from user store " + e);
                }
            } else if(log.isDebugEnabled()) {
                log.debug("Subject claim for " + tenantAwareUserId + " not found in user store");
            }
        } catch (UserStoreException var6) {
            log.error("Error occurred while retrieving " + subjectURI + " claim value for user " + tenantAwareUserId, var6);
        }

    }

    private void addMultiAttributeSperatorToRequestedClaims(AuthenticatedUser authenticatedUser, org.wso2.carbon.user.core.UserStoreManager userStore, Map<String, String> spRequestedClaims) {
        if(!spRequestedClaims.isEmpty()) {
            RealmConfiguration realmConfiguration = userStore.getRealmConfiguration();
            String claimSeparator = realmConfiguration.getUserStoreProperty("MultiAttributeSeparator");
            if(StringUtils.isNotBlank(claimSeparator)) {
                spRequestedClaims.put("MultiAttributeSeparator", claimSeparator);
            }
        }

    }

}
