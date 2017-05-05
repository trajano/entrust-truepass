package net.trajano.entrust.jaspic.sample;

import javax.servlet.annotation.WebListener;

import net.trajano.entrust.jaspic.BaseEntrustTruePassServletContextInitializer;
import net.trajano.entrust.jaspic.EntrustTruePassPrincipalProvider;

@WebListener
public class JaspicInitializer extends BaseEntrustTruePassServletContextInitializer {

    private final SamplePrincipalProvider provider = new SamplePrincipalProvider();

    @Override
    protected EntrustTruePassPrincipalProvider getPrincipalProvider() {

        return provider;
    }

}
