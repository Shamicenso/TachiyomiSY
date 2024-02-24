package eu.kanade.tachiyomi.util.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.hippo.unifile.UniFile
import eu.kanade.tachiyomi.core.security.SecurityPreferences
import eu.kanade.tachiyomi.util.lang.compareToCaseInsensitiveNaturalOrder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import logcat.LogPriority
import net.lingala.zip4j.exception.ZipException
import net.lingala.zip4j.io.inputstream.ZipInputStream
import net.lingala.zip4j.io.outputstream.ZipOutputStream
import net.lingala.zip4j.model.LocalFileHeader
import net.lingala.zip4j.model.ZipParameters
import net.lingala.zip4j.model.enums.AesKeyStrength
import net.lingala.zip4j.model.enums.EncryptionMethod
import tachiyomi.core.common.util.system.ImageUtil
import tachiyomi.core.common.util.system.logcat
import uy.kohesive.injekt.injectLazy
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

// SY -->
/**
 * object used to En/Decrypt and Base64 en/decode
 * passwords before storing
 * them in Shared Preferences
 */
object CbzCrypto {
    const val DATABASE_NAME = "tachiyomiEncrypted.db"
    const val DEFAULT_COVER_NAME = "cover.jpg"
    private val securityPreferences: SecurityPreferences by injectLazy()
    private val keyStore = KeyStore.getInstance(KEYSTORE).apply {
        load(null)
    }

    private val encryptionCipherCbz
        get() = Cipher.getInstance(CRYPTO_SETTINGS).apply {
            init(
                Cipher.ENCRYPT_MODE,
                getKey(ALIAS_CBZ),
            )
        }

    private val encryptionCipherSql
        get() = Cipher.getInstance(CRYPTO_SETTINGS).apply {
            init(
                Cipher.ENCRYPT_MODE,
                getKey(ALIAS_SQL),
            )
        }

    private fun getDecryptCipher(iv: ByteArray, alias: String): Cipher {
        return Cipher.getInstance(CRYPTO_SETTINGS).apply {
            init(
                Cipher.DECRYPT_MODE,
                getKey(alias),
                IvParameterSpec(iv),
            )
        }
    }

    private fun getKey(alias: String): SecretKey {
        val loadedKey = keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry
        return loadedKey?.secretKey ?: generateKey(alias)
    }

    private fun generateKey(alias: String): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(KEY_SIZE)
                    .setBlockModes(BLOCK_MODE)
                    .setEncryptionPaddings(PADDING)
                    .setRandomizedEncryptionRequired(true)
                    .setUserAuthenticationRequired(false)
                    .build(),
            )
        }.generateKey()
    }

    private fun encrypt(password: String, cipher: Cipher): String {
        val outputStream = ByteArrayOutputStream()
        outputStream.use { output ->
            output.write(cipher.iv)
            ByteArrayInputStream(password.toByteArray()).use { input ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (input.available() > BUFFER_SIZE) {
                    input.read(buffer)
                    output.write(cipher.update(buffer))
                }
                output.write(cipher.doFinal(input.readBytes()))
            }
        }
        return Base64.encodeToString(outputStream.toByteArray(), Base64.DEFAULT)
    }

    private fun decrypt(encryptedPassword: String, alias: String): String {
        val inputStream = Base64.decode(encryptedPassword, Base64.DEFAULT).inputStream()
        return inputStream.use { input ->
            val iv = ByteArray(IV_SIZE)
            input.read(iv)
            val cipher = getDecryptCipher(iv, alias)
            ByteArrayOutputStream().use { output ->
                val buffer = ByteArray(BUFFER_SIZE)
                while (inputStream.available() > BUFFER_SIZE) {
                    inputStream.read(buffer)
                    output.write(cipher.update(buffer))
                }
                output.write(cipher.doFinal(inputStream.readBytes()))
                output.toString()
            }
        }
    }

    fun deleteKeyCbz() {
        keyStore.deleteEntry(ALIAS_CBZ)
        generateKey(ALIAS_CBZ)
    }

    fun encryptCbz(password: String): String {
        return encrypt(password, encryptionCipherCbz)
    }

    fun getDecryptedPasswordCbz(): CharArray {
        return decrypt(securityPreferences.cbzPassword().get(), ALIAS_CBZ).toCharArray()
    }

    private fun generateAndEncryptSqlPw() {
        val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
        val password = (1..32).map {
            charPool[SecureRandom().nextInt(charPool.size)]
        }.joinToString("", transform = { it.toString() })
        securityPreferences.sqlPassword().set(encrypt(password, encryptionCipherSql))
    }

    fun getDecryptedPasswordSql(): ByteArray {
        if (securityPreferences.sqlPassword().get().isBlank()) generateAndEncryptSqlPw()
        return decrypt(securityPreferences.sqlPassword().get(), ALIAS_SQL).toByteArray()
    }

    fun isPasswordSet(): Boolean {
        return securityPreferences.cbzPassword().get().isNotEmpty()
    }

    fun isPasswordSetState(scope: CoroutineScope): StateFlow<Boolean> {
        return securityPreferences.cbzPassword().changes()
            .map { it.isNotEmpty() }
            .stateIn(scope, SharingStarted.Eagerly, false)
    }

    fun getPasswordProtectDlPref(): Boolean {
        return securityPreferences.passwordProtectDownloads().get()
    }

    fun createComicInfoPadding(): String? {
        return if (getPasswordProtectDlPref()) {
            val charPool: List<Char> = ('a'..'z') + ('A'..'Z') + ('0'..'9')
            List(SecureRandom().nextInt(100) + 42) { charPool.random() }.joinToString("")
        } else {
            null
        }
    }

    private fun setZipParametersEncrypted(zipParameters: ZipParameters) {
        zipParameters.isEncryptFiles = true

        when (securityPreferences.encryptionType().get()) {
            SecurityPreferences.EncryptionType.AES_256 -> {
                zipParameters.encryptionMethod = EncryptionMethod.AES
                zipParameters.aesKeyStrength = AesKeyStrength.KEY_STRENGTH_256
            }

            SecurityPreferences.EncryptionType.AES_192 -> {
                zipParameters.encryptionMethod = EncryptionMethod.AES
                zipParameters.aesKeyStrength = AesKeyStrength.KEY_STRENGTH_192
            }

            SecurityPreferences.EncryptionType.AES_128 -> {
                zipParameters.encryptionMethod = EncryptionMethod.AES
                zipParameters.aesKeyStrength = AesKeyStrength.KEY_STRENGTH_128
            }

            SecurityPreferences.EncryptionType.ZIP_STANDARD -> {
                zipParameters.encryptionMethod = EncryptionMethod.ZIP_STANDARD
            }
        }
    }

    fun detectCoverImageArchive(stream: InputStream): Boolean {
        val bytes = ByteArray(128)
        if (stream.markSupported()) {
            stream.mark(bytes.size)
            stream.read(bytes, 0, bytes.size).also { stream.reset() }
        } else {
            stream.read(bytes, 0, bytes.size)
        }
        return String(bytes).contains(DEFAULT_COVER_NAME, ignoreCase = true)
    }

    fun UniFile.isEncryptedZip(): Boolean {
        return try {
            val stream = ZipInputStream(this.openInputStream())
            stream.nextEntry
            stream.close()
            false
        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                true
            } else throw zipException
        }
    }

    fun UniFile.testCbzPassword(): Boolean {
        return try {
            val stream = ZipInputStream(this.openInputStream())
            stream.setPassword(getDecryptedPasswordCbz())
            stream.nextEntry
            stream.close()
            true
        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                false
            } else throw zipException
        }
    }

    fun UniFile.addStreamToZip(inputStream: InputStream, filename: String, password: CharArray? = null) {
        val zipOutputStream =
            if (password != null) ZipOutputStream(this.openOutputStream(), password)
            else ZipOutputStream(this.openOutputStream())

        val zipParameters = ZipParameters()
        zipParameters.fileNameInZip = filename

        if (password != null) setZipParametersEncrypted(zipParameters)
        zipOutputStream.putNextEntry(zipParameters)

        zipOutputStream.use { output ->
            inputStream.use { input ->
                input.copyTo(output)
            }
        }
    }


    fun UniFile.addFilesToZip(files: List<UniFile>, password: CharArray? = null) {
        val zipOutputStream =
            if (password != null) ZipOutputStream(this.openOutputStream(), password)
            else ZipOutputStream(this.openOutputStream())


        files.forEach {
            val zipParameters = ZipParameters()
            if (password != null) setZipParametersEncrypted(zipParameters)
            zipParameters.fileNameInZip = it.name

            zipOutputStream.putNextEntry(zipParameters)

            it.openInputStream().use { input ->
                input.copyTo(zipOutputStream)
            }
            zipOutputStream.closeEntry()
        }
        zipOutputStream.close()
    }

    fun UniFile.getZipInputStream(filename: String): InputStream? {
        val zipInputStream = ZipInputStream(this.openInputStream())
        var fileHeader: LocalFileHeader?

        if (this.isEncryptedZip()) zipInputStream.setPassword(getDecryptedPasswordCbz())

        try {
            while (run {
                    fileHeader = zipInputStream.nextEntry
                    fileHeader != null
                }) {
                if (fileHeader?.fileName == filename) return zipInputStream
            }

        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                logcat(LogPriority.WARN) {
                    "Wrong CBZ archive password for: ${this.name} in: ${this.parentFile?.name}"
                }
            } else throw zipException
        }
        return null
    }

    fun UniFile.getZipInputStreamUnsafe(filename: String, encrypted: Boolean = false): InputStream {
        val zipInputStream = ZipInputStream(this.openInputStream())
        var fileHeader: LocalFileHeader?

        if (encrypted) zipInputStream.setPassword(getDecryptedPasswordCbz())
        else {
            if (this.isEncryptedZip()) zipInputStream.setPassword(getDecryptedPasswordCbz())
        }

        while (run {
                fileHeader = zipInputStream.nextEntry
                fileHeader != null
            }) {
            if (fileHeader?.fileName == filename) return zipInputStream
        }
        return zipInputStream
    }

    fun UniFile.getCoverStreamFromZip(): InputStream? {
        val zipInputStream = ZipInputStream(this.openInputStream())
        var fileHeader: LocalFileHeader?
        val fileHeaderList: MutableList<LocalFileHeader?> = mutableListOf()

        if (this.isEncryptedZip()) zipInputStream.setPassword(getDecryptedPasswordCbz())

        try {
            while (run {
                    fileHeader = zipInputStream.nextEntry
                    fileHeader != null
                }) {
                fileHeaderList.add(fileHeader)
            }

            val coverHeader = fileHeaderList
                .mapNotNull { it }
                .sortedWith { f1, f2 -> f1.fileName.compareToCaseInsensitiveNaturalOrder(f2.fileName) }
                .find { !it.isDirectory && ImageUtil.isImage(it.fileName) { getZipInputStreamUnsafe(it.fileName) } }

            return coverHeader?.fileName?.let { getZipInputStream(it) }

        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                logcat(LogPriority.WARN) {
                    "Wrong CBZ archive password for: ${this.name} in: ${this.parentFile?.name}"
                }
                return null
            } else throw zipException
        }
    }

    fun UniFile.getZipFileHeaders(): MutableList<LocalFileHeader?> {
        val zipInputStream = ZipInputStream(this.openInputStream())
        var fileHeader: LocalFileHeader?
        val fileHeaderList: MutableList<LocalFileHeader?> = mutableListOf()

        if (this.isEncryptedZip()) zipInputStream.setPassword(getDecryptedPasswordCbz())

        try {
            while (run {
                    fileHeader = zipInputStream.nextEntry
                    fileHeader != null
                }) {
                fileHeaderList.add(fileHeader)
            }
            return fileHeaderList

        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                logcat(LogPriority.WARN) {
                    "Wrong CBZ archive password for: ${this.name} in: ${this.parentFile?.name}"
                }
                return mutableListOf()
            } else throw zipException
        }
    }

    fun UniFile.unzip(destination: File, onlyExtractImages: Boolean = false) {
        var zipInputStream = ZipInputStream(this.openInputStream())
        var fileHeader: LocalFileHeader?
        val fileHeaderList: MutableList<LocalFileHeader?> = mutableListOf()
        var encrypted = false

        if (this.isEncryptedZip()) {
            zipInputStream.setPassword(getDecryptedPasswordCbz())
            encrypted = true
        }

        try {
            while (run {
                    fileHeader = zipInputStream.nextEntry
                    fileHeader != null
                }) {
                fileHeaderList.add(fileHeader)
            }

            val images = fileHeaderList
                .mapNotNull { it }
                .filter { !it.isDirectory && ImageUtil.isImage(it.fileName) { getZipInputStreamUnsafe(it.fileName) } }

            zipInputStream = ZipInputStream(this.openInputStream())
            if (encrypted) {
                zipInputStream.setPassword(getDecryptedPasswordCbz())
            }

            while (run {
                    fileHeader = zipInputStream.nextEntry
                    fileHeader != null
                }) {
                if (fileHeader in images) {
                    val destFile = File("${destination.absolutePath}/${fileHeader?.fileName}")
                    destFile.createNewFile()
                    destFile.outputStream().use { output ->
                        zipInputStream.use { input ->
                            input.copyTo(output)
                        }
                    }
                }
            }
        } catch (zipException: ZipException) {
            if (zipException.type == ZipException.Type.WRONG_PASSWORD) {
                logcat(LogPriority.WARN) {
                    "Wrong CBZ archive password for: ${this.name} in: ${this.parentFile?.name}"
                }
            } else throw zipException
        }
    }
}

private const val BUFFER_SIZE = 2048
private const val KEY_SIZE = 256
private const val IV_SIZE = 16

private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
private const val CRYPTO_SETTINGS = "$ALGORITHM/$BLOCK_MODE/$PADDING"

private const val KEYSTORE = "AndroidKeyStore"
private const val ALIAS_CBZ = "cbzPw"
private const val ALIAS_SQL = "sqlPw"
// SY <--
