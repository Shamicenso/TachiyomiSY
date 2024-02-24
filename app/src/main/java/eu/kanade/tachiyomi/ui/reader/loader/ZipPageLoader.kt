package eu.kanade.tachiyomi.ui.reader.loader

import android.app.Application
import com.hippo.unifile.UniFile
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.ui.reader.model.ReaderPage
import eu.kanade.tachiyomi.ui.reader.setting.ReaderPreferences
import eu.kanade.tachiyomi.util.lang.compareToCaseInsensitiveNaturalOrder
import eu.kanade.tachiyomi.util.storage.CbzCrypto.getZipFileHeaders
import eu.kanade.tachiyomi.util.storage.CbzCrypto.getZipInputStreamUnsafe
import eu.kanade.tachiyomi.util.storage.CbzCrypto.isEncryptedZip
import eu.kanade.tachiyomi.util.storage.CbzCrypto.testCbzPassword
import eu.kanade.tachiyomi.util.storage.CbzCrypto.unzip
import tachiyomi.core.common.i18n.stringResource
import tachiyomi.core.common.util.system.ImageUtil
import tachiyomi.i18n.sy.SYMR
import uy.kohesive.injekt.injectLazy
import java.io.File

/**
 * Loader used to load a chapter from a .zip or .cbz file.
 */
internal class ZipPageLoader(file: UniFile) : PageLoader() {

    // SY -->
    private val context: Application by injectLazy()
    private val readerPreferences: ReaderPreferences by injectLazy()
    private val uniFile = file
    private var encrypted = false
    private val tmpDir = File(context.externalCacheDir, "reader_${file.hashCode()}").also {
        it.deleteRecursively()
    }

    init {
        if (file.isEncryptedZip()) {
            encrypted = true
            if (!file.testCbzPassword()) {
                this.recycle()
                throw IllegalStateException(context.stringResource(SYMR.strings.wrong_cbz_archive_password))
            }
        }
        if (readerPreferences.cacheArchiveMangaOnDisk().get()) {
            file.unzip(tmpDir, onlyExtractImages = true)
        }
    }


    // SY <--
    override fun recycle() {
        super.recycle()
        // SY -->
        tmpDir.deleteRecursively()
    }

    override var isLocal: Boolean = true

    override suspend fun getPages(): List<ReaderPage> {
        if (readerPreferences.cacheArchiveMangaOnDisk().get()) {
            return DirectoryPageLoader(UniFile.fromFile(tmpDir)!!).getPages()
        }
        return uniFile.getZipFileHeaders()
            .asSequence()
            .mapNotNull { it }
            .filter { !it.isDirectory && ImageUtil.isImage(it.fileName) {
                uniFile.getZipInputStreamUnsafe(it.fileName) }
            }
            .sortedWith { f1, f2 -> f1.fileName.compareToCaseInsensitiveNaturalOrder(f2.fileName) }
            .mapIndexed { i, entry ->
                ReaderPage(i).apply {
                    stream = { uniFile.getZipInputStreamUnsafe(entry.fileName) }
                    status = Page.State.READY
                    zip4jFile = uniFile
                    zip4jEntry = entry
                }
            }.toList()
    }

    /**
     * No additional action required to load the page
     */
    override suspend fun loadPage(page: ReaderPage) {
        check(!isRecycled)
    }
}
