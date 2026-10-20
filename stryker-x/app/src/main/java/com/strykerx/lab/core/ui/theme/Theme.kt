package com.strykerx.lab.core.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val StrykerColors = darkColorScheme(
    primary = AmberGold,
    onPrimary = NoirBlack,
    secondary = TealGlow,
    onSecondary = NoirBlack,
    tertiary = AmberDim,
    background = NoirBlack,
    onBackground = TextPrimary,
    surface = NoirPanel,
    onSurface = TextPrimary,
    surfaceVariant = NoirSurface,
    onSurfaceVariant = TextSecondary,
    outline = NoirOutline,
    error = SevCritical,
    onError = TextPrimary
)

@Composable
fun StrykerXTheme(
    @Suppress("UNUSED_PARAMETER") darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    // STRYKER X is a dark-only cybersecurity theme by design.
    MaterialTheme(
        colorScheme = StrykerColors,
        typography = Typography(),
        content = content
    )
}
