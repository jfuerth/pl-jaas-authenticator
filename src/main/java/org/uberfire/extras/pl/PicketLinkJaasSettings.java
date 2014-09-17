package org.uberfire.extras.pl;


public class PicketLinkJaasSettings {

    public static final String DEFAULT_DOMAIN = "ApplicationRealm";
    public static final String DEFAULT_ROLE_PRINCIPAL_NAME = "Roles";

    private String domain = DEFAULT_DOMAIN;
    private String rolePrincipalName = DEFAULT_ROLE_PRINCIPAL_NAME;

    public String getDomain() {
        return domain;
    }


    public void setDomain( String domain ) {
        this.domain = domain;
    }



    public String getRolePrincipalName() {
        return rolePrincipalName;
    }



    public void setRolePrincipalName( String rolePrincipalName ) {
        this.rolePrincipalName = rolePrincipalName;
    }

}
