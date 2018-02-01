package com.zeva.tlgen.utils.dsig;

import java.io.File;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.util.List;

import xades4j.providers.impl.FileSystemKeyStoreKeyingDataProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyEntryPasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.KeyStorePasswordProvider;
import xades4j.providers.impl.KeyStoreKeyingDataProvider.SigningCertSelector;

public class FileSystemKeyStoreKeyingDataProviderFactory {

	public static FileSystemKeyStoreKeyingDataProvider createFileSystemKeyingDataProvider(
            String keyStoreType,
            String keyStorePath,
            final String keyStorePwd,
            boolean returnFullChain) throws KeyStoreException
    {
        keyStorePath = keyStorePath.replace('/', File.separatorChar);
        SigningCertSelector certSelector = new SigningCertSelector() {
			
			@Override
			public X509Certificate selectCertificate(
					List<X509Certificate> availableCertificates) {
				return availableCertificates.get(0);
			}
		};
		
		KeyStorePasswordProvider ksPasswordProvider = new KeyStorePasswordProvider() {
			
			@Override
			public char[] getPassword() {
				return keyStorePwd.toCharArray();
			}
		};
		
		KeyEntryPasswordProvider kePasswordProvider = new KeyEntryPasswordProvider() {
			
			@Override
			public char[] getPassword(String entryAlias,
					X509Certificate entryCert) {
				return keyStorePwd.toCharArray();
			}
		};
		
        
        
        return new FileSystemKeyStoreKeyingDataProvider(
        		keyStoreType,
        		keyStorePath, 
        		certSelector, 
        		ksPasswordProvider, 
        		kePasswordProvider, 
        		returnFullChain);
    }
	
}
