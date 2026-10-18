package com.strykerx.lab

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.LayoutDirection
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.strykerx.lab.core.i18n.LocalAppLanguage
import com.strykerx.lab.core.ui.theme.StrykerXTheme
import com.strykerx.lab.navigation.StrykerNavHost

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val container = (application as StrykerApp).container
        setContent {
            val language by container.settings.language.collectAsStateWithLifecycle()
            val direction = if (language.rtl) LayoutDirection.Rtl else LayoutDirection.Ltr
            StrykerXTheme {
                CompositionLocalProvider(
                    LocalAppLanguage provides language,
                    LocalLayoutDirection provides direction
                ) {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        StrykerNavHost(container)
                    }
                }
            }
        }
    }
}
