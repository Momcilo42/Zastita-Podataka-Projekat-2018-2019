package implementation;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.x509.extension.X509ExtensionUtil;

import code.GuiException;
import gui.Constants;
import x509.v3.CodeV3;

@SuppressWarnings("deprecation")
public class MyCode extends CodeV3 {

	private static final String KEY_STORE_FILE = "keyStoreFile.p12";
	private static final String KEY_STORE_PASSW = "sifra";

	private KeyStore localKeyStore;
	private static Provider bouncyCastleProvider = new BouncyCastleProvider();
	
	private PKCS10CertificationRequest importedCSR;

	public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
		super(algorithm_conf, extensions_conf, extensions_rules);
	}

	@Override
	public boolean canSign(String keyPair) {
		try {
			X509Certificate x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
			Extension basicConstraintsExtension = x509CertificateHolder.getExtension(Extension.basicConstraints);
			if (basicConstraintsExtension == null)
				return false;
			BasicConstraints basicConstraints = BasicConstraints
					.fromExtensions(new Extensions(basicConstraintsExtension));
			return basicConstraints.isCA();
		} catch (KeyStoreException | CertificateEncodingException | IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCSR(String file, String keyPair, String algorithm) {
		try {
			X509Certificate x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
			PublicKey publicKey = x509Certificate.getPublicKey();
			PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(keyPair, KEY_STORE_PASSW.toCharArray());
			X500Name x500NameSubject = x509CertificateHolder.getSubject();
			JcaPKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
					x500NameSubject, publicKey);
			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build((PrivateKey) privateKey);
			PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestBuilder
					.build(contentSigner);
			FileWriter fileWriter = new FileWriter(file);
			JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
			pemWriter.writeObject(pkcs10CertificationRequest);
			pemWriter.close();
			return true;
		} catch (KeyStoreException | CertificateEncodingException | IOException | OperatorCreationException
				| UnrecoverableKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportCertificate(String file, String keyPair, int encoding, int format) {
		try {
			X509Certificate x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			Certificate[] certificateChain = localKeyStore.getCertificateChain(keyPair);
			FileOutputStream fos = new FileOutputStream(file);
			if (encoding == Constants.DER)
				fos.write(x509Certificate.getEncoded());
			if (encoding == Constants.PEM) {
				FileWriter fileWriter = new FileWriter(file);
				JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter);
				if (format == Constants.HEAD)
					pemWriter.writeObject(x509Certificate);
				if (format == Constants.CHAIN)
					for (Certificate certificate : certificateChain)
						pemWriter.writeObject(certificate);
				pemWriter.close();
			}
			fos.close();
			return true;
		} catch (KeyStoreException | IOException | CertificateEncodingException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean exportKeypair(String keyPair, String file, String password) {
		try {
			KeyStore keyStore = KeyStore.getInstance("pkcs12", bouncyCastleProvider);
			keyStore.load(null, password.toCharArray());
			char[] charPassword = password.toCharArray();
			Certificate[] certificateChain = localKeyStore.getCertificateChain(keyPair);
			Key key = localKeyStore.getKey(keyPair, KEY_STORE_PASSW.toCharArray());
			keyStore.setKeyEntry(keyPair, key, charPassword, certificateChain);
			storeKeyStore(file, keyStore, password);
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String getCertPublicKeyAlgorithm(String keyPair) {
		String publicKeyAlgorithm = "None known";
		try {
			String s = localKeyStore.getCertificate(keyPair).getPublicKey().getAlgorithm();
			if ("DSA".equals(s) || "RSA".equals(s) || "EC".equals(s))
				publicKeyAlgorithm = s;
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return publicKeyAlgorithm;
	}

	@Override
	public String getCertPublicKeyParameter(String keyPair) {
		String publicKeyParameter = "None known";
		try {
			PublicKey publicKey = localKeyStore.getCertificate(keyPair).getPublicKey();
			String s = publicKey.getAlgorithm();
			if ("DSA".equals(s)) {
//				DSAPublicKey dsaPK = (DSAPublicKey) publicKey;
//				publicKeyParameter = String.valueOf(dsaPK.getParams().getP().bitLength());
				publicKeyParameter = "1024";
			}
			if ("RSA".equals(s)) {
//				RSAPublicKey rsaPK = (RSAPublicKey) publicKey;
//				publicKeyParameter = String.valueOf(rsaPK.getModulus().bitLength());
				publicKeyParameter = "1024";
			}
			if ("EC".equals(s)) {
				SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
						.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()));
				String ECcurve = subjectPublicKeyInfo.getAlgorithm().getParameters().toString();
				String curveName = org.bouncycastle.asn1.x9.ECNamedCurveTable
						.getName(new ASN1ObjectIdentifier(ECcurve));
				publicKeyParameter = curveName;
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}
		return publicKeyParameter;
	}

	@Override
	public String getSubjectInfo(String keyPair) {
		X509Certificate x509Certificate;
		String subjectInfo = "";
		try {
			x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
			X500Name x500NameSubject = x509CertificateHolder.getSubject();
			if (x500NameSubject.getRDNs(BCStyle.CN).length > 0)
				subjectInfo += "CN=" + x500NameSubject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.C).length > 0)
				subjectInfo += ",C=" + x500NameSubject.getRDNs(BCStyle.C)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.ST).length > 0)
				subjectInfo += ",S=" + x500NameSubject.getRDNs(BCStyle.ST)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.L).length > 0)
				subjectInfo += ",L=" + x500NameSubject.getRDNs(BCStyle.L)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.O).length > 0)
				subjectInfo += ",O=" + x500NameSubject.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.OU).length > 0)
				subjectInfo += ",OU=" + x500NameSubject.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();
			subjectInfo += ",SA=" + getCertPublicKeyAlgorithm(keyPair);
		} catch (KeyStoreException | CertificateEncodingException | IOException e) {
			e.printStackTrace();
		}
		return subjectInfo;
	}

	@Override
	public boolean importCAReply(String file, String keyPair) {
		try {
			FileInputStream fis = new FileInputStream(new File(file));
			CMSSignedData cmsSignedData = new CMSSignedData(fis);
			Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
            Collection<X509CertificateHolder> collection = store.getMatches(null);
            X509Certificate[] certificateChain = new X509Certificate[collection.size()];
            int i = 0;
            for (X509CertificateHolder holder : collection)
                certificateChain[i++] = 
                new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
            PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(keyPair, KEY_STORE_PASSW.toCharArray());
			localKeyStore.deleteEntry(keyPair);
			localKeyStore.setKeyEntry(keyPair, privateKey, KEY_STORE_PASSW.toCharArray(), certificateChain);
			storeKeyStore(file, localKeyStore, KEY_STORE_PASSW);
			return true;
		} catch (FileNotFoundException | CMSException | KeyStoreException | CertificateException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public String importCSR(String file) {
		try {
			FileReader fileReader = new FileReader(file);
			PemReader pemReader = new PemReader(fileReader);
			JcaPKCS10CertificationRequest pkcs10CertificationRequest = new JcaPKCS10CertificationRequest(
					pemReader.readPemObject().getContent());
			importedCSR = pkcs10CertificationRequest;
			X500Name x500NameSubject = pkcs10CertificationRequest.getSubject();
			AlgorithmIdentifier algorithmIdentifier = pkcs10CertificationRequest.getSignatureAlgorithm();
			String signatureAlgorithm = new DefaultAlgorithmNameFinder().getAlgorithmName(algorithmIdentifier);
			String retValue = x500NameSubject.toString() + "," + "SA=" + signatureAlgorithm;
			pemReader.close();
			return retValue;
		} catch (IOException e) {
			e.printStackTrace();
			return "";
		}
	}

	@Override
	public boolean importCertificate(String file, String keyPair) {
		try {
			FileInputStream fis = new FileInputStream(file);
			CertificateFactory certificateFactory = new CertificateFactory();
			X509Certificate x509Certificate = (X509Certificate) certificateFactory.engineGenerateCertificate(fis);
			localKeyStore.setCertificateEntry(keyPair, x509Certificate);
			storeKeyStore(KEY_STORE_FILE, localKeyStore, KEY_STORE_PASSW);
			fis.close();
			return true;
		} catch (CertificateException | KeyStoreException | IOException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public boolean importKeypair(String keyPair, String file, String password) {
		try {
			FileInputStream fis = new FileInputStream(file);
			KeyStore keyStore = KeyStore.getInstance("pkcs12");
			char[] charPassword = password.toCharArray();
			keyStore.load(fis, charPassword);
			fis.close();
			String alias = keyStore.aliases().nextElement();
			Key key = keyStore.getKey(alias, charPassword);
			Certificate[] certificateChain = keyStore.getCertificateChain(alias);
			localKeyStore.setKeyEntry(keyPair, key, charPassword, certificateChain);
			storeKeyStore(KEY_STORE_FILE, localKeyStore, KEY_STORE_PASSW);
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
				| UnrecoverableKeyException e) {
			e.printStackTrace();
		}
		return false;
	}

	@Override
	public int loadKeypair(String keyPair) {
		Boolean isca = false;
		Boolean selfsigned = false;
		try {
			if (!localKeyStore.containsAlias(keyPair)) {
				return -1;
			}
			X509Certificate x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			PublicKey publicKey = x509Certificate.getPublicKey();
			SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
					.getInstance(ASN1Sequence.getInstance(publicKey.getEncoded()));

			int version = x509Certificate.getVersion();
			BigInteger serialNumber = x509Certificate.getSerialNumber();
			Date notBefore = x509Certificate.getNotBefore();
			Date notAfter = x509Certificate.getNotAfter();
			if (version == 3)
				access.setVersion(Constants.V3);
			access.setSerialNumber(serialNumber.toString());
			access.setNotBefore(notBefore);
			access.setNotAfter(notAfter);

			String algorithmSHA = x509Certificate.getSigAlgName().toString();
			String ECcurve = subjectPublicKeyInfo.getAlgorithm().getParameters().toString();
			String curveName = "";
			if (getCertPublicKeyAlgorithm(keyPair).equals("EC"))
				curveName = org.bouncycastle.asn1.x9.ECNamedCurveTable.getName(new ASN1ObjectIdentifier(ECcurve));
			access.setPublicKeyDigestAlgorithm(algorithmSHA);
			access.setPublicKeyECCurve(curveName);

			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
			Extension subjectKeyIdentifierExtension = x509CertificateHolder
					.getExtension(Extension.subjectKeyIdentifier);
			Extension subjectDirectoryAttributesExtension = x509CertificateHolder
					.getExtension(Extension.subjectDirectoryAttributes);
			Extension basicConstraintsExtension = x509CertificateHolder.getExtension(Extension.basicConstraints);
			if (subjectKeyIdentifierExtension != null) {
				access.setCritical(Constants.SKID, subjectKeyIdentifierExtension.isCritical());
				access.setEnabledSubjectKeyID(true);
				access.setSubjectKeyID(subjectKeyIdentifierExtension.getExtnId().toString());
			}

			if (subjectDirectoryAttributesExtension != null) {
				access.setCritical(Constants.SDA, subjectDirectoryAttributesExtension.isCritical());
				byte[] subjectDirectoryAttributesBytes = x509Certificate
						.getExtensionValue(Extension.subjectDirectoryAttributes.toString());
				SubjectDirectoryAttributes subjectDirectoryAttributes = SubjectDirectoryAttributes
						.getInstance(X509ExtensionUtil.fromExtensionValue(subjectDirectoryAttributesBytes));
				@SuppressWarnings("unchecked")
				Vector<Attribute> subjectDirectoryAttributesVector = subjectDirectoryAttributes.getAttributes();
				for (Attribute attribute : subjectDirectoryAttributesVector) {
					String subjectDirectoryAttributesType = attribute.getAttrType().toString();
					String subjectDirectoryAttributesValue = attribute.getAttrValues().toString();
					subjectDirectoryAttributesValue = subjectDirectoryAttributesValue.substring(1,
							subjectDirectoryAttributesValue.length() - 1);
					if (subjectDirectoryAttributesType.equals(BCStyle.DATE_OF_BIRTH.toString()))
						access.setDateOfBirth(subjectDirectoryAttributesValue);
					else if (subjectDirectoryAttributesType.equals(BCStyle.PLACE_OF_BIRTH.toString()))
						access.setSubjectDirectoryAttribute(Constants.POB, subjectDirectoryAttributesValue);
					else if (subjectDirectoryAttributesType.equals(BCStyle.COUNTRY_OF_CITIZENSHIP.toString()))
						access.setSubjectDirectoryAttribute(Constants.COC, subjectDirectoryAttributesValue);
					else if (subjectDirectoryAttributesType.equals(BCStyle.GENDER.toString()))
						access.setGender(subjectDirectoryAttributesValue);
				}
			}

			String siCountry = "";
			String siState = "";
			String siLocality = "";
			String siOrganization = "";
			String siOrganizationUnit = "";
			String siCommonName = "";
			String siPublicKeyAlgorithm = "";

			X500Name x500NameSubject = x509CertificateHolder.getSubject();
			if (x500NameSubject.getRDNs(BCStyle.C).length > 0)
				siCountry = x500NameSubject.getRDNs(BCStyle.C)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.ST).length > 0)
				siState = x500NameSubject.getRDNs(BCStyle.ST)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.L).length > 0)
				siLocality = x500NameSubject.getRDNs(BCStyle.L)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.O).length > 0)
				siOrganization = x500NameSubject.getRDNs(BCStyle.O)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.OU).length > 0)
				siOrganizationUnit = x500NameSubject.getRDNs(BCStyle.OU)[0].getFirst().getValue().toString();
			if (x500NameSubject.getRDNs(BCStyle.CN).length > 0)
				siCommonName = x500NameSubject.getRDNs(BCStyle.CN)[0].getFirst().getValue().toString();
			siPublicKeyAlgorithm = publicKey.getAlgorithm();
			access.setSubjectCountry(siCountry);
			access.setSubjectState(siState);
			access.setSubjectLocality(siLocality);
			access.setSubjectOrganization(siOrganization);
			access.setSubjectOrganizationUnit(siOrganizationUnit);
			access.setSubjectCommonName(siCommonName);
			access.setSubjectSignatureAlgorithm(siPublicKeyAlgorithm);
			access.setPublicKeyAlgorithm("EC");

			X500Name x500NameIssuer = x509CertificateHolder.getIssuer();
			access.setIssuer(x500NameIssuer.toString());
			access.setIssuerSignatureAlgorithm(x509Certificate.getSigAlgName());

			if (x509Certificate.getSubjectDN().equals(x509Certificate.getIssuerDN()))
				selfsigned = true;

			if (basicConstraintsExtension != null) {
				BasicConstraints basicConstraints = BasicConstraints
						.fromExtensions(new Extensions(basicConstraintsExtension));
				access.setCritical(Constants.BC, basicConstraintsExtension.isCritical());
				access.setCA(basicConstraints.isCA());
				if (basicConstraints.getPathLenConstraint() != null)
					access.setPathLen(basicConstraints.getPathLenConstraint().toString());
				isca = basicConstraints.isCA();
			}

			if (isca)
				return 2;
			else if (selfsigned)
				return 0; 
			else
				return 1;

		} catch (KeyStoreException | CertificateEncodingException | IOException e) {
			e.printStackTrace();
		}
		return -1;
	}

	@Override
	public Enumeration<String> loadLocalKeystore() {
		FileInputStream fis = null;
		try {
			if (localKeyStore == null) {
				localKeyStore = KeyStore.getInstance("pkcs12", bouncyCastleProvider);
				localKeyStore.load(null, KEY_STORE_PASSW.toCharArray());
				return localKeyStore.aliases();
			}
			fis = new FileInputStream(KEY_STORE_FILE);
			localKeyStore.load(fis, KEY_STORE_PASSW.toCharArray());
			fis.close();
			return localKeyStore.aliases();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public boolean removeKeypair(String keypair) {
		try {
			localKeyStore.deleteEntry(keypair);
			storeKeyStore(KEY_STORE_FILE, localKeyStore, KEY_STORE_PASSW);
		} catch (KeyStoreException e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	public void storeKeyStore(String file, KeyStore keyStore, String password) {
		FileOutputStream fos;
		try {
			fos = new FileOutputStream(file);
			keyStore.store(fos, password.toCharArray());
			fos.close();
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void resetLocalKeystore() {
		if (localKeyStore == null)
			return;
		try {
			bouncyCastleProvider = new BouncyCastleProvider();
			localKeyStore = KeyStore.getInstance("pkcs12", bouncyCastleProvider);
			localKeyStore.load(null, KEY_STORE_PASSW.toCharArray());
			storeKeyStore(KEY_STORE_FILE, localKeyStore, KEY_STORE_PASSW);
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}
	}

	@Override
	public boolean saveKeypair(String keypair) {
		try {
			if (localKeyStore.containsAlias(keypair))
				return false;
			String ECalgorithm = access.getPublicKeyAlgorithm();
			String ECcurve = access.getPublicKeyECCurve();
			String ECsha = access.getPublicKeyDigestAlgorithm();

			ECParameterSpec ecParameterSpec = ECNamedCurveTable.getParameterSpec(ECcurve);

			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ECalgorithm, bouncyCastleProvider);
			keyPairGenerator.initialize(ecParameterSpec);
			KeyPair keyPair = keyPairGenerator.genKeyPair();
			ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
			ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

			String subjectInfo = "";
			String parameter = access.getSubjectCommonName();
			if (parameter.length() > 0)
				subjectInfo += "CN=" + parameter;
			parameter = access.getSubjectCountry();
			if (parameter.length() > 0)
				subjectInfo += ",C=" + parameter;
			parameter = access.getSubjectState();
			if (parameter.length() > 0)
				subjectInfo += ",ST=" + parameter;
			parameter = access.getSubjectLocality();
			if (parameter.length() > 0)
				subjectInfo += ",L=" + parameter;
			parameter = access.getSubjectOrganization();
			if (parameter.length() > 0)
				subjectInfo += ",O=" + parameter;
			parameter = access.getSubjectOrganizationUnit();
			if (parameter.length() > 0)
				subjectInfo += ",OU=" + parameter;
			X500Name x500Name = new X500Name(subjectInfo);

			X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(x500Name,
					new BigInteger(access.getSerialNumber()), access.getNotBefore(), access.getNotAfter(), x500Name,
					publicKey);

			addCertificateExtensions(x509v3CertificateBuilder, publicKey);

			ContentSigner contentSigner = new JcaContentSignerBuilder(ECsha).build(privateKey);
			X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(bouncyCastleProvider)
					.getCertificate(x509v3CertificateBuilder.build(contentSigner));
			localKeyStore.setKeyEntry(keypair, privateKey, KEY_STORE_PASSW.toCharArray(),
					new X509Certificate[] { x509Certificate });
			storeKeyStore(KEY_STORE_FILE, localKeyStore, KEY_STORE_PASSW);
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | OperatorCreationException | CertificateException
				| InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return false;
	}

	public void addCertificateExtensions(X509v3CertificateBuilder x509v3CertificateBuilder, PublicKey publicKey) {
		try {
			SubjectKeyIdentifier subjectKeyIdentifier = null;
			Boolean subjectKeyIdentifierIsCritical = access.isCritical(Constants.SKID);
			Boolean subjectKeyIdentifierIsEnabled = access.getEnabledSubjectKeyID();
			SubjectPublicKeyInfo subjectPublicKeyInfo = null;
			if (subjectKeyIdentifierIsEnabled) {
				subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
				subjectKeyIdentifier = new SubjectKeyIdentifier(subjectPublicKeyInfo.getEncoded());
			}

			SubjectDirectoryAttributes subjectDirectoryAttributes = null;
			Boolean subjectDirectoryAttributesIsCritical = access.isCritical(Constants.SDA);
			String subjectDirectoryAttributesDateOfBirth = access.getDateOfBirth();
			String subjectDirectoryAttributesPlaceOfBirth = access.getSubjectDirectoryAttribute(0);
			String subjectDirectoryAttributesCountryOfCitizenship = access.getSubjectDirectoryAttribute(1);
			String subjectDirectoryAttributesGender = access.getGender();
			Vector<Attribute> subjectDirectoryAttributeAttributes = new Vector<>();
			subjectDirectoryAttributeAttributes.add(new Attribute(BCStyle.DATE_OF_BIRTH,
					new DERSet(new DERGeneralString(subjectDirectoryAttributesDateOfBirth))));
			subjectDirectoryAttributeAttributes.add(new Attribute(BCStyle.PLACE_OF_BIRTH,
					new DERSet(new DERGeneralString(subjectDirectoryAttributesPlaceOfBirth))));
			subjectDirectoryAttributeAttributes.add(new Attribute(BCStyle.COUNTRY_OF_CITIZENSHIP,
					new DERSet(new DERGeneralString(subjectDirectoryAttributesCountryOfCitizenship))));
			subjectDirectoryAttributeAttributes.add(
					new Attribute(BCStyle.GENDER, new DERSet(new DERGeneralString(subjectDirectoryAttributesGender))));
			subjectDirectoryAttributes = new SubjectDirectoryAttributes(subjectDirectoryAttributeAttributes);

			BasicConstraints basicConstraints = null;
			Integer basicConstraintsPathLength = 0;
			Boolean basicConstraintsIsCA = access.isCA();
			Boolean basicConstraintsIsCritical = access.isCritical(Constants.BC);
			if (!access.getPathLen().isEmpty())
				basicConstraintsPathLength = Integer.parseInt(access.getPathLen());
			if (basicConstraintsPathLength > 0 && basicConstraintsIsCA)
				basicConstraints = new BasicConstraints(basicConstraintsPathLength);
			else
				basicConstraints = new BasicConstraints(basicConstraintsIsCA);

			Extension subjectKeyIdentifierExtension = null;
			Extension subjectDirectoryAttributesExtension = null;
			Extension basicConstraintsExtension = null;
			if (subjectKeyIdentifier != null)
				subjectKeyIdentifierExtension = new Extension(Extension.subjectKeyIdentifier,
						subjectKeyIdentifierIsCritical, subjectKeyIdentifier.getEncoded());
			if (subjectDirectoryAttributes != null)
				subjectDirectoryAttributesExtension = new Extension(Extension.subjectDirectoryAttributes,
						subjectDirectoryAttributesIsCritical, subjectDirectoryAttributes.getEncoded());

			if (basicConstraints != null)
				basicConstraintsExtension = new Extension(Extension.basicConstraints, basicConstraintsIsCritical,
						basicConstraints.getEncoded());

			if (subjectKeyIdentifierExtension != null)
				x509v3CertificateBuilder.addExtension(subjectKeyIdentifierExtension);
			if (subjectDirectoryAttributesExtension != null)
				x509v3CertificateBuilder.addExtension(subjectDirectoryAttributesExtension);
			if (basicConstraintsExtension != null)
				x509v3CertificateBuilder.addExtension(basicConstraintsExtension);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Override
	public boolean signCSR(String file, String keyPair, String algorithm) {
		//mora u configu da bude ukljucen RSA jer je ETFrootCA RSA
		//i ako nije ukljuceno gui puca kad treba da selektuje RSA radio button
		try {
			FileOutputStream fos = new FileOutputStream(file);
			X509Certificate x509Certificate = (X509Certificate) localKeyStore.getCertificate(keyPair);
			X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(x509Certificate.getEncoded());
			X500Name x500NameSubject = importedCSR.getSubject();
			PublicKey publicKey = new JcaPKCS10CertificationRequest(importedCSR).setProvider(bouncyCastleProvider).getPublicKey();
			X500Name x500NameIssuer = x509CertificateHolder.getIssuer();
			X509v3CertificateBuilder x509v3CertificateBuilder = new JcaX509v3CertificateBuilder(
					x500NameIssuer,
					new BigInteger(access.getSerialNumber()), 
					access.getNotBefore(), 
					access.getNotAfter(),
					x500NameSubject, 
					publicKey);
			addCertificateExtensions(x509v3CertificateBuilder, publicKey);
			PrivateKey privateKey = (PrivateKey) localKeyStore.getKey(keyPair, KEY_STORE_PASSW.toCharArray());
			ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm).build((PrivateKey) privateKey);
			X509Certificate x509CertificateSigned = 
					new JcaX509CertificateConverter().getCertificate(x509v3CertificateBuilder.build(contentSigner));
			CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			CMSTypedData cmsTypedData = new CMSProcessableByteArray(x509CertificateSigned.getEncoded());
			List<JcaX509CertificateHolder> certificateChain = new ArrayList<>();
            certificateChain.add(new JcaX509CertificateHolder(x509CertificateSigned));
            for(Certificate certificate :  localKeyStore.getCertificateChain(keyPair))
                certificateChain.add(new JcaX509CertificateHolder((X509Certificate) certificate));
            cmsSignedDataGenerator.addCertificates(new CollectionStore(certificateChain));
            CMSSignedData cmsSignedData = cmsSignedDataGenerator.generate(cmsTypedData);
			fos.write(cmsSignedData.getEncoded());
			fos.close();
			return true;
		} catch (KeyStoreException | IOException | UnrecoverableKeyException
				| NoSuchAlgorithmException | OperatorCreationException | CertificateException | CMSException | InvalidKeyException e) {
			e.printStackTrace();
		}
		return false;
	}

}
