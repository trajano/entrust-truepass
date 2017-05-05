package net.trajano.entrust.jaspic;

/**
 * Implementers of this interface will provide the principal data used for the
 * callbacks.
 */
public interface EntrustTruePassPrincipalProvider {

    String getPrincipalNameFromEntrustToken(String entrustToken);

    /**
     * Builds a list of groups from the entrust token. This value must match the
     * security-roles in web.xml.
     *
     * @param entrustToken
     *            decoded entrust token
     * @return array of groups.
     */
    String[] getGroupsFromEntrustToken(String entrustToken);
}
