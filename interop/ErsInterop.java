// Interoperability tests with Bouncy Castle's org.bouncycastle.tsp.ers
// (docs/design.md, chapter 9). Run by test/interop/bouncy_castle_test.rb:
//
//   java -cp 'interop/lib/*' interop/ErsInterop.java verify MANIFEST
//   java -cp 'interop/lib/*' interop/ErsInterop.java generate DIR
//
// verify: checks Evidence Records with Bouncy Castle. Each line of MANIFEST
//   is "ER TSA_CERT KIND DATA..." (paths separated by single spaces): ER is
//   the record (DER), TSA_CERT the certificate of the TSA that made its last
//   time-stamp (DER), KIND "object" or "group", and DATA the files of the data
//   object or of the group members. Prints one line per record: "OK", or
//   "NG <reason>".
//
// generate: builds Evidence Records with Bouncy Castle and its own test TSA
//   into DIR, with the data files they cover and the TSA's root certificate
//   (see generate below for the files).
//
// Uses only the Java standard library and the Bouncy Castle jars.

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.tsp.ers.ERSArchiveTimeStampGenerator;
import org.bouncycastle.tsp.ers.ERSByteData;
import org.bouncycastle.tsp.ers.ERSData;
import org.bouncycastle.tsp.ers.ERSDataGroup;
import org.bouncycastle.tsp.ers.ERSEvidenceRecord;
import org.bouncycastle.tsp.ers.ERSEvidenceRecordGenerator;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.jcajce.JcaCertStore;

public class ErsInterop
{
    static final DigestCalculatorProvider DIGESTS;

    static
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            DIGESTS = new JcaDigestCalculatorProviderBuilder().build();
        }
        catch (Exception e)
        {
            throw new IllegalStateException(e);
        }
    }

    public static void main(String[] args)
        throws Exception
    {
        if (args.length == 2 && args[0].equals("verify"))
        {
            verify(Paths.get(args[1]));
        }
        else if (args.length == 2 && args[0].equals("generate"))
        {
            generate(Paths.get(args[1]));
        }
        else
        {
            System.err.println("usage: ErsInterop verify MANIFEST | generate DIR");
            System.exit(2);
        }
    }

    // --- verify ------------------------------------------------------------------------

    static void verify(Path manifest)
        throws IOException
    {
        for (String line : Files.readAllLines(manifest, StandardCharsets.UTF_8))
        {
            if (line.isEmpty())
            {
                continue;
            }
            String[] f = line.split(" ");
            try
            {
                verifyOne(Paths.get(f[0]), Paths.get(f[1]), f[2], Arrays.copyOfRange(f, 3, f.length));
                System.out.println("OK");
            }
            catch (Exception e)
            {
                System.out.println("NG " + e.getClass().getSimpleName() + ": " + String.valueOf(e.getMessage()).replace('\n', ' '));
            }
        }
    }

    static void verifyOne(Path erPath, Path certPath, String kind, String[] dataPaths)
        throws Exception
    {
        byte[] der = Files.readAllBytes(erPath);
        // The constructor checks that each time-stamp of a chain covers the
        // one before.
        ERSEvidenceRecord er = new ERSEvidenceRecord(der, DIGESTS);
        // The data in the first time-stamp of the last chain (with the hash
        // of the older chains), and the signature of the last time-stamp,
        // which must cover all the time-stamps of its chain.
        er.validatePresent(data(kind, dataPaths), new Date());
        X509CertificateHolder cert = new X509CertificateHolder(Files.readAllBytes(certPath));
        er.validate(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
        // Bouncy Castle re-encodes the parsed record as DER; it must come out
        // the same.
        if (!Arrays.equals(der, er.toASN1Structure().getEncoded(ASN1Encoding.DER)))
        {
            throw new IllegalStateException("the record is not encoded as Bouncy Castle encodes it in DER");
        }
    }

    static ERSData data(String kind, String[] paths)
        throws IOException
    {
        List<ERSData> members = new ArrayList<ERSData>();
        for (String p : paths)
        {
            members.add(new ERSByteData(Files.readAllBytes(Paths.get(p))));
        }
        if (kind.equals("object"))
        {
            if (members.size() != 1)
            {
                throw new IllegalArgumentException("a data object needs exactly one file");
            }
            return members.get(0);
        }
        if (kind.equals("group"))
        {
            return new ERSDataGroup(members);
        }
        throw new IllegalArgumentException("unknown kind: " + kind);
    }

    // --- generate ----------------------------------------------------------------------

    // Writes into dir:
    //   root.cer                the TSA's root certificate
    //   h1.bin h2.bin h3a.bin h3b.bin h3c.bin  the data
    //   init-0.ers init-1.ers init-2.ers  h1, h2 and the group h3a-c in one tree (SHA-256)
    //   single.ers              h1 alone
    //   ts-0.ers ts-2.ers       init-0 / init-2 renewed by time-stamp, sharing one response;
    //                           ts-2 is renewed twice (three time-stamps)
    //   hash-0.ers hash-2.ers   ts-0 / ts-2 renewed by hash tree with SHA-512, then by
    //                           time-stamp
    static void generate(Path dir)
        throws Exception
    {
        Files.createDirectories(dir);
        TestTsa tsa = new TestTsa();
        Files.write(dir.resolve("root.cer"), tsa.root.getEncoded());

        byte[][] files = {
            bytes("This is H1"), bytes("This is H2"), bytes("This is H3A"), bytes("This is H3B"), bytes("This is H3C")};
        String[] names = {"h1.bin", "h2.bin", "h3a.bin", "h3b.bin", "h3c.bin"};
        for (int i = 0; i != files.length; i++)
        {
            Files.write(dir.resolve(names[i]), files[i]);
        }
        ERSData h1 = new ERSByteData(files[0]);
        ERSData h2 = new ERSByteData(files[1]);
        ERSDataGroup h3 = new ERSDataGroup(new ERSData[]{
            new ERSByteData(files[2]), new ERSByteData(files[3]), new ERSByteData(files[4])});

        DigestCalculator sha256 = DIGESTS.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        DigestCalculator sha512 = DIGESTS.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha512));
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);

        ERSArchiveTimeStampGenerator gen = new ERSArchiveTimeStampGenerator(sha256);
        gen.addData(h1);
        gen.addData(h2);
        gen.addData(h3);
        List<ERSEvidenceRecord> init = new ERSEvidenceRecordGenerator(DIGESTS).generate(
            gen.generateArchiveTimeStamps(tsa.respond(gen.generateTimeStampRequest(reqGen))));
        for (int i = 0; i != 3; i++)
        {
            write(dir, "init-" + i + ".ers", init.get(i));
        }

        gen = new ERSArchiveTimeStampGenerator(sha256);
        gen.addData(h1);
        ERSEvidenceRecord single = new ERSEvidenceRecordGenerator(DIGESTS).generate(
            gen.generateArchiveTimeStamps(tsa.respond(gen.generateTimeStampRequest(reqGen)))).get(0);
        write(dir, "single.ers", single);

        TimeStampResponse shared = tsa.respond(init.get(2).generateTimeStampRenewalRequest(reqGen));
        ERSEvidenceRecord ts0 = init.get(0).renewTimeStamp(shared);
        ERSEvidenceRecord ts2 = init.get(2).renewTimeStamp(shared);
        ts2 = ts2.renewTimeStamp(tsa.respond(ts2.generateTimeStampRenewalRequest(reqGen)));
        write(dir, "ts-0.ers", ts0);
        write(dir, "ts-2.ers", ts2);

        ERSEvidenceRecord hash0 = ts0.renewHash(sha512, h1, tsa.respond(ts0.generateHashRenewalRequest(sha512, h1, reqGen)));
        hash0 = hash0.renewTimeStamp(tsa.respond(hash0.generateTimeStampRenewalRequest(reqGen)));
        ERSEvidenceRecord hash2 = ts2.renewHash(sha512, h3, tsa.respond(ts2.generateHashRenewalRequest(sha512, h3, reqGen)));
        hash2 = hash2.renewTimeStamp(tsa.respond(hash2.generateTimeStampRenewalRequest(reqGen)));
        write(dir, "hash-0.ers", hash0);
        write(dir, "hash-2.ers", hash2);
    }

    static byte[] bytes(String s)
    {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static void write(Path dir, String name, ERSEvidenceRecord er)
        throws IOException
    {
        Files.write(dir.resolve(name), er.getEncoded());
    }

    // A test TSA: an EC root certificate and a TSA certificate issued by it.
    // Time-stamps are made one minute apart, starting ten minutes ago.
    static class TestTsa
    {
        final X509CertificateHolder root;
        final X509CertificateHolder cert;
        final PrivateKey key;
        long time = System.currentTimeMillis() - 10 * 60 * 1000;
        int serial = 0;

        TestTsa()
            throws Exception
        {
            KeyPair rootKey = ecKey();
            KeyPair tsaKey = ecKey();
            X500Name rootName = new X500Name("CN=evidence_record interop root");
            Date from = new Date(time - 24L * 3600 * 1000);
            Date to = new Date(time + 365L * 24 * 3600 * 1000);

            JcaX509v3CertificateBuilder rb = new JcaX509v3CertificateBuilder(rootName, BigInteger.ONE, from, to, rootName, rootKey.getPublic());
            rb.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rb.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            root = rb.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(rootKey.getPrivate()));

            JcaX509v3CertificateBuilder tb = new JcaX509v3CertificateBuilder(rootName, BigInteger.TWO, from, to,
                new X500Name("CN=evidence_record interop TSA"), tsaKey.getPublic());
            tb.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
            tb.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            cert = tb.build(new JcaContentSignerBuilder("SHA256withECDSA").setProvider("BC").build(rootKey.getPrivate()));
            key = tsaKey.getPrivate();
        }

        static KeyPair ecKey()
            throws Exception
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "BC");
            kpg.initialize(new ECGenParameterSpec("P-256"));
            return kpg.generateKeyPair();
        }

        TimeStampResponse respond(TimeStampRequest request)
            throws Exception
        {
            DigestCalculator essDigest = DIGESTS.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
            TimeStampTokenGenerator tokenGen = new TimeStampTokenGenerator(
                new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withECDSA", key, cert),
                essDigest, new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.2"));
            Store certs = new JcaCertStore(Arrays.asList(cert, root));
            tokenGen.addCertificates(certs);
            TimeStampResponseGenerator respGen = new TimeStampResponseGenerator(tokenGen, TSPAlgorithms.ALLOWED);
            time += 60 * 1000;
            TimeStampResponse response = respGen.generateGrantedResponse(request, BigInteger.valueOf(++serial), new Date(time));
            if (response.getTimeStampToken() == null)
            {
                throw new IllegalStateException("the test TSA rejected the request: " + response.getStatusString());
            }
            return response;
        }
    }
}
