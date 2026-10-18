package com.strykerx.lab.core.ui.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val StrykerColors = darkColorScheme(
    primary = ElectricCyan,
    onPrimary = DeepNavy,
    secondary = EmeraldGreen,
    onSecondary = DeepNavy,
    tertiary = CyanDim,
    background = DeepNavy,
    onBackground = TextPrimary,
    surface = PanelNavy,
    onSurface = TextPrimary,
    surfaceVariant = SurfaceNavy,
    onSurfaceVariant = TextSecondary,
    outline = OutlineNavy,
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
