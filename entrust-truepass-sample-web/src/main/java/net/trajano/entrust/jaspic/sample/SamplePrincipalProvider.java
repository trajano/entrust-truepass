package net.trajano.entrust.jaspic.sample;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import net.trajano.entrust.jaspic.EntrustTruePassPrincipalProvider;

public class SamplePrincipalProvider implements
    EntrustTruePassPrincipalProvider {

    @Override
    public String getPrincipalNameFromEntrustToken(String entrustToken) {

        try {
            LdapName ln = new LdapName(entrustToken);

            for (Rdn rdn : ln.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("serial")) {
                    return (String) rdn.getValue();
                }
            }
            throw new RuntimeException("unable to extract principal");
        } catch (InvalidNameException e) {
            throw new RuntimeException("unable to extract principal", e);
        }
    }

    @Override
    public String[] getGroupsFromEntrustToken(String entrustToken) {

        return new String[] {
            "users"
        };
    }

}
