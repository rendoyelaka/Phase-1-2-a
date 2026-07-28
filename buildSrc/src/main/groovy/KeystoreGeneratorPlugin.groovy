import org.gradle.api.Plugin
import org.gradle.api.Project

class KeystoreGeneratorPlugin implements Plugin<Project> {

    private static final List<String> NAMES = [
        // Indian names (primary — matches app target market)
        "Rahul Sharma","Priya Verma","Amit Patel","Sneha Iyer",
        "Vikram Singh","Deepika Nair","Arjun Mehta","Pooja Gupta",
        "Kiran Reddy","Suresh Kumar","Ananya Pillai","Ravi Bhatia",
        "Meena Joshi","Sanjay Dubey","Kavitha Menon","Rohit Yadav",
        // Western names (secondary — diversity)
        "Alice","Bob","Charlie","David","Eve","Frank","Grace","Hank",
        "Ivy","Jack","Karen","Leo","Mia","Nina","Oscar","Paul"
    ]
    private static final List<String> ORGS = [
        // Indian orgs (primary — matches app target market)
        "Bharat Digital Services","India Tech Solutions",
        "Desi Apps Studio","Hindustan Mobile Works",
        "Bharat Soft Labs","IndiaNet Technologies",
        "Digi Seva Solutions","Sampark Tech India",
        // Western orgs (secondary — diversity)
        "Acme Corp","Bright Solutions","Cloud Nine","Delta Systems",
        "Echo Labs","Fusion Works","Globe Tech","Horizon Inc",
        "Quantum Works","Rapid Tech","Stellar Inc","Titan Group"
    ]
    private static final List<String> CITIES = [
        "Austin","Boston","Chicago","Denver","Eugene","Fresno",
        "Gilbert","Houston","Irving","Jacksonville","Kansas City",
        "Louisville","Memphis","Nashville","Omaha","Portland",
        "Quincy","Raleigh","Salem","Tucson"
    ]
    private static final List<String> STATES = [
        "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA",
        "HI","ID","IL","IN","IA","KS","KY","LA","ME","MD",
        "MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ"
    ]
    private static final List<String> COUNTRIES = [
        // IN weighted 3x — primary target market
        "IN","IN","IN",
        "US","GB","DE","FR","CA","AU","JP","NL","SE","NO",
        "FI","DK","CH","AT","NZ","SG","IE","BE","IT","ES"
    ]

    @Override
    void apply(Project project) {
        def ext = project.extensions.create('keystoreGenerator', KeystoreGeneratorExtension)

        def outputDir = new File(project.buildDir, 'keystore')
        outputDir.mkdirs()

        // Clean up any leftover keystores from previous builds (secure wipe)
        outputDir.listFiles()?.each { f ->
            if (f.name.endsWith('.jks') || f.name.endsWith('.keystore')) secureWipe(f, project)
        }

        def cn       = pick(NAMES)
        def ou       = pick(ORGS) + " Dev"
        def o        = pick(ORGS)
        def l        = pick(CITIES)
        def st       = pick(STATES)
        def c        = pick(COUNTRIES)
        def alias    = "key_" + randomAlpha(8)
        def pass     = randomAlpha(20)
        def validity = randomInt(730, 3650)
        def ksName   = "ks_${project.name}_${randomAlpha(10)}.jks"
        def ksFile   = new File(outputDir, ksName)
        def dname    = "CN=${cn}, OU=${ou}, O=${o}, L=${l}, ST=${st}, C=${c}"

        def cmd = [
            "keytool", "-genkeypair",
            "-storetype", "JKS",
            "-keystore",  ksFile.absolutePath,
            "-alias",     alias,
            "-keyalg",    "RSA",
            "-keysize",   "2048",
            "-validity",  validity.toString(),
            "-storepass", pass,
            "-keypass",   pass,
            "-dname",     dname,
            "-noprompt"
        ]

        def proc = cmd.execute()
        def stderr = new StringBuilder()
        proc.consumeProcessErrorStream(stderr)
        proc.waitFor()

        if (proc.exitValue() != 0 || !ksFile.exists()) {
            throw new org.gradle.api.GradleException(
                "[KeystoreGeneratorPlugin] keytool failed:\n${stderr}"
            )
        }

        project.ext.ks_storeFile = ksFile
        project.ext.ks_storePass = pass
        project.ext.ks_keyAlias  = alias
        project.ext.ks_keyPass   = pass

        project.logger.lifecycle("[KeystoreGeneratorPlugin] ✅ Keystore: ${ksFile.name} | CN=${cn} | C=${c} | validity=${validity}d")

        // Write credentials to a temp properties file so generate_batch.sh
        // can re-sign the APK after Phase 2 post-processing scripts modify it.
        // The file is wiped in buildFinished (same pass as the keystore).
        def credsFile = new File(outputDir, "ks_creds_${project.name}.properties")
        credsFile.text = """ks_file=${ksFile.absolutePath}
ks_pass=${pass}
ks_alias=${alias}
"""
        project.ext.ks_credsFile = credsFile.absolutePath
        project.logger.lifecycle("[KeystoreGeneratorPlugin] 📝 Credentials written: ${credsFile.name}")

        // The .jks keystore and ks_creds_*.properties are intentionally NOT
        // wiped in buildFinished. generate_batch.sh must re-sign the Nova APK
        // after Phase 2 post-processing scripts modify it. It needs the .jks
        // and creds file to still exist at that point.
        // generate_batch.sh performs the secure 3-pass wipe of both files
        // after re-signing and verification complete.
        project.logger.lifecycle("[KeystoreGeneratorPlugin] ℹ️  Keystore wipe deferred to generate_batch.sh post-resign")
    }

    /**
     * Step 6: Multi-pass secure wipe.
     * Pass 1: overwrite with 0x00
     * Pass 2: overwrite with 0xFF
     * Pass 3: overwrite with random bytes
     * Then delete.
     */
    static void secureWipe(File file, Project project) {
        if (!file.exists()) return
        try {
            long len = file.length()
            if (len > 0) {
                def rng = new java.security.SecureRandom()

                // Pass 1 — zeros
                file.withOutputStream { os ->
                    def zeros = new byte[4096]
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        os.write(zeros, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }

                // Pass 2 — 0xFF
                file.withOutputStream { os ->
                    def ones = new byte[4096]
                    java.util.Arrays.fill(ones, (byte) 0xFF)
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        os.write(ones, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }

                // Pass 3 — random
                file.withOutputStream { os ->
                    def buf = new byte[4096]
                    long written = 0
                    while (written < len) {
                        int chunk = (int) Math.min(4096L, len - written)
                        rng.nextBytes(buf)
                        os.write(buf, 0, chunk)
                        written += chunk
                    }
                    os.flush()
                }
            }
            file.delete()
            project.logger.lifecycle("[KeystoreGeneratorPlugin] 🔒 Secure wiped (3-pass): ${file.name}")
        } catch (Exception e) {
            // Fallback — at minimum delete the file
            file.delete()
            project.logger.warn("[KeystoreGeneratorPlugin] ⚠️ Wipe failed, deleted: ${file.name} — ${e.message}")
        }
    }

    static String pick(List<String> list) { list[(int)(Math.random() * list.size())] }
    static String randomAlpha(int len) {
        def chars = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        (1..len).collect { chars[(int)(Math.random() * chars.size())] }.join('')
    }
    static int randomInt(int min, int max) { min + (int)(Math.random() * (max - min + 1)) }
}

class KeystoreGeneratorExtension {
    File   outputDir
    String label
}
