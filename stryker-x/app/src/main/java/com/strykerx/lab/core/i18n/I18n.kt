package com.strykerx.lab.core.i18n

import androidx.compose.runtime.staticCompositionLocalOf

/** Languages offered by the in-app language center. */
enum class AppLanguage(val code: String, val englishName: String, val nativeName: String, val rtl: Boolean) {
    EN("en", "English", "English", false),
    AR("ar", "Arabic", "العربية", true),
    FR("fr", "French", "Français", false),
    ES("es", "Spanish", "Español", false),
    DE("de", "German", "Deutsch", false),
    TR("tr", "Turkish", "Türkçe", false),
    RU("ru", "Russian", "Русский", false);

    companion object {
        val DEFAULT = EN
        fun from(code: String?): AppLanguage =
            entries.firstOrNull { it.code.equals(code, true) || it.name.equals(code, true) } ?: DEFAULT
    }
}

/** Current language, provided from the top of the Compose tree. */
val LocalAppLanguage = staticCompositionLocalOf { AppLanguage.DEFAULT }

/** Look up a translation key for a language, falling back to English then the key. */
fun t(key: String, lang: AppLanguage): String {
    val row = Strings.TABLE[key] ?: return key
    return row[lang] ?: row[AppLanguage.EN] ?: key
}

/**
 * Translation table: key -> (language -> text). English is the fallback.
 * Only UI chrome is translated; technical finding text stays in English by design.
 */
object Strings {
    val TABLE: Map<String, Map<AppLanguage, String>> = mapOf(
        "app_subtitle" to mapOf(
            AppLanguage.EN to "SECURITY INVESTIGATOR",
            AppLanguage.AR to "محقّق أمني",
            AppLanguage.FR to "ENQUÊTEUR SÉCURITÉ",
            AppLanguage.ES to "INVESTIGADOR DE SEGURIDAD",
            AppLanguage.DE to "SICHERHEITS-ERMITTLER",
            AppLanguage.TR to "GÜVENLİK DEDEKTİFİ",
            AppLanguage.RU to "СЛЕДОВАТЕЛЬ БЕЗОПАСНОСТИ"
        ),
        "nav_dashboard" to mapOf(
            AppLanguage.EN to "Dashboard", AppLanguage.AR to "الرئيسية", AppLanguage.FR to "Tableau",
            AppLanguage.ES to "Panel", AppLanguage.DE to "Übersicht", AppLanguage.TR to "Panel", AppLanguage.RU to "Панель"
        ),
        "nav_web" to mapOf(
            AppLanguage.EN to "Web", AppLanguage.AR to "المواقع", AppLanguage.FR to "Web",
            AppLanguage.ES to "Web", AppLanguage.DE to "Web", AppLanguage.TR to "Web", AppLanguage.RU to "Веб"
        ),
        "nav_apk" to mapOf(
            AppLanguage.EN to "APK", AppLanguage.AR to "تطبيقات", AppLanguage.FR to "APK",
            AppLanguage.ES to "APK", AppLanguage.DE to "APK", AppLanguage.TR to "APK", AppLanguage.RU to "APK"
        ),
        "nav_network" to mapOf(
            AppLanguage.EN to "Network", AppLanguage.AR to "الشبكة", AppLanguage.FR to "Réseau",
            AppLanguage.ES to "Red", AppLanguage.DE to "Netzwerk", AppLanguage.TR to "Ağ", AppLanguage.RU to "Сеть"
        ),
        "nav_findings" to mapOf(
            AppLanguage.EN to "Findings", AppLanguage.AR to "النتائج", AppLanguage.FR to "Résultats",
            AppLanguage.ES to "Hallazgos", AppLanguage.DE to "Befunde", AppLanguage.TR to "Bulgular", AppLanguage.RU to "Находки"
        ),
        "dash_completed" to mapOf(
            AppLanguage.EN to "Completed Scans", AppLanguage.AR to "فحوصات مكتملة", AppLanguage.FR to "Scans terminés",
            AppLanguage.ES to "Escaneos completos", AppLanguage.DE to "Abgeschlossen", AppLanguage.TR to "Tamamlanan", AppLanguage.RU to "Завершено"
        ),
        "dash_active" to mapOf(
            AppLanguage.EN to "Active Scans", AppLanguage.AR to "فحوصات نشطة", AppLanguage.FR to "Scans actifs",
            AppLanguage.ES to "Escaneos activos", AppLanguage.DE to "Aktive Scans", AppLanguage.TR to "Aktif", AppLanguage.RU to "Активные"
        ),
        "dash_potential" to mapOf(
            AppLanguage.EN to "Potential", AppLanguage.AR to "محتملة", AppLanguage.FR to "Potentiel",
            AppLanguage.ES to "Potencial", AppLanguage.DE to "Potenziell", AppLanguage.TR to "Olası", AppLanguage.RU to "Возможные"
        ),
        "dash_confirmed" to mapOf(
            AppLanguage.EN to "Confirmed", AppLanguage.AR to "مؤكّدة", AppLanguage.FR to "Confirmé",
            AppLanguage.ES to "Confirmado", AppLanguage.DE to "Bestätigt", AppLanguage.TR to "Onaylı", AppLanguage.RU to "Подтверждено"
        ),
        "dash_severity" to mapOf(
            AppLanguage.EN to "Severity Distribution", AppLanguage.AR to "توزيع الخطورة", AppLanguage.FR to "Répartition de gravité",
            AppLanguage.ES to "Distribución de gravedad", AppLanguage.DE to "Schweregrad-Verteilung", AppLanguage.TR to "Önem dağılımı", AppLanguage.RU to "Распределение серьёзности"
        ),
        "dash_device" to mapOf(
            AppLanguage.EN to "Device Resource Status", AppLanguage.AR to "حالة موارد الجهاز", AppLanguage.FR to "Ressources de l'appareil",
            AppLanguage.ES to "Recursos del dispositivo", AppLanguage.DE to "Geräte-Ressourcen", AppLanguage.TR to "Cihaz kaynakları", AppLanguage.RU to "Ресурсы устройства"
        ),
        "dash_recent" to mapOf(
            AppLanguage.EN to "Recent Activity", AppLanguage.AR to "النشاط الأخير", AppLanguage.FR to "Activité récente",
            AppLanguage.ES to "Actividad reciente", AppLanguage.DE to "Letzte Aktivität", AppLanguage.TR to "Son etkinlik", AppLanguage.RU to "Недавняя активность"
        ),
        "dash_quickstart" to mapOf(
            AppLanguage.EN to "Quick Start Scan", AppLanguage.AR to "ابدأ فحصاً سريعاً", AppLanguage.FR to "Démarrage rapide",
            AppLanguage.ES to "Escaneo rápido", AppLanguage.DE to "Schnellscan", AppLanguage.TR to "Hızlı tarama", AppLanguage.RU to "Быстрый скан"
        ),
        "dash_no_scans" to mapOf(
            AppLanguage.EN to "No scans yet.", AppLanguage.AR to "لا فحوصات بعد.", AppLanguage.FR to "Aucun scan.",
            AppLanguage.ES to "Sin escaneos.", AppLanguage.DE to "Noch keine Scans.", AppLanguage.TR to "Henüz tarama yok.", AppLanguage.RU to "Пока нет сканов."
        ),
        "web_title" to mapOf(
            AppLanguage.EN to "Website Scanner", AppLanguage.AR to "فاحص المواقع", AppLanguage.FR to "Scanner de site",
            AppLanguage.ES to "Escáner web", AppLanguage.DE to "Website-Scanner", AppLanguage.TR to "Web tarayıcı", AppLanguage.RU to "Сканер сайтов"
        ),
        "web_subtitle" to mapOf(
            AppLanguage.EN to "Authorized, non-destructive checks", AppLanguage.AR to "فحوصات مصرّح بها وغير تدميرية",
            AppLanguage.FR to "Contrôles autorisés et non destructifs", AppLanguage.ES to "Comprobaciones autorizadas",
            AppLanguage.DE to "Autorisiert, zerstörungsfrei", AppLanguage.TR to "Yetkili, tahribatsız", AppLanguage.RU to "Авторизованные проверки"
        ),
        "web_authz_notice" to mapOf(
            AppLanguage.EN to "Authorized testing only. A URL does not grant permission. Scans are locked to the target host and rate-limited.",
            AppLanguage.AR to "للفحص المصرّح به فقط. امتلاك الرابط ليس إذناً. الفحص مقيّد بالمضيف الهدف ومحدود المعدّل.",
            AppLanguage.FR to "Tests autorisés uniquement. Une URL n'accorde aucune permission.",
            AppLanguage.ES to "Solo pruebas autorizadas. Una URL no otorga permiso.",
            AppLanguage.DE to "Nur autorisierte Tests. Eine URL erteilt keine Erlaubnis.",
            AppLanguage.TR to "Yalnızca yetkili testler. URL izin vermez.",
            AppLanguage.RU to "Только авторизованное тестирование. URL не даёт разрешения."
        ),
        "web_target" to mapOf(
            AppLanguage.EN to "Target URL  (https://example.com)", AppLanguage.AR to "الهدف  (https://example.com)",
            AppLanguage.FR to "URL cible", AppLanguage.ES to "URL objetivo", AppLanguage.DE to "Ziel-URL", AppLanguage.TR to "Hedef URL", AppLanguage.RU to "Целевой URL"
        ),
        "web_allowlist" to mapOf(
            AppLanguage.EN to "Additional in-scope hosts (optional, one per line)",
            AppLanguage.AR to "مضيفات إضافية ضمن النطاق (اختياري، واحد بكل سطر)",
            AppLanguage.FR to "Hôtes supplémentaires autorisés (optionnel)",
            AppLanguage.ES to "Hosts adicionales en alcance (opcional)",
            AppLanguage.DE to "Weitere erlaubte Hosts (optional)",
            AppLanguage.TR to "Kapsamdaki ek ana bilgisayarlar (isteğe bağlı)",
            AppLanguage.RU to "Доп. хосты в области (необязательно)"
        ),
        "web_authorized" to mapOf(
            AppLanguage.EN to "I am authorized to scan this target", AppLanguage.AR to "أنا مخوّل لفحص هذا الهدف",
            AppLanguage.FR to "Je suis autorisé à scanner cette cible", AppLanguage.ES to "Estoy autorizado a escanear",
            AppLanguage.DE to "Ich bin zum Scannen berechtigt", AppLanguage.TR to "Bu hedefi taramaya yetkiliyim", AppLanguage.RU to "Я уполномочен сканировать цель"
        ),
        "web_active_tests" to mapOf(
            AppLanguage.EN to "Enable opt-in active checks (XSS/SQLi on URL params)",
            AppLanguage.AR to "تفعيل الفحوصات النشطة الاختيارية (XSS/SQLi على باراميترات الرابط)",
            AppLanguage.FR to "Activer les tests actifs (XSS/SQLi)",
            AppLanguage.ES to "Habilitar pruebas activas (XSS/SQLi)",
            AppLanguage.DE to "Aktive Tests aktivieren (XSS/SQLi)",
            AppLanguage.TR to "Aktif testleri etkinleştir (XSS/SQLi)",
            AppLanguage.RU to "Включить активные проверки (XSS/SQLi)"
        ),
        "web_internal" to mapOf(
            AppLanguage.EN to "Allow internal/private network targets", AppLanguage.AR to "السماح بأهداف الشبكة الداخلية/الخاصة",
            AppLanguage.FR to "Autoriser les cibles réseau internes", AppLanguage.ES to "Permitir objetivos de red interna",
            AppLanguage.DE to "Interne Netzwerkziele erlauben", AppLanguage.TR to "İç ağ hedeflerine izin ver", AppLanguage.RU to "Разрешить внутренние цели"
        ),
        "web_start" to mapOf(
            AppLanguage.EN to "START SCAN", AppLanguage.AR to "ابدأ الفحص", AppLanguage.FR to "DÉMARRER",
            AppLanguage.ES to "INICIAR", AppLanguage.DE to "SCAN STARTEN", AppLanguage.TR to "TARAMAYI BAŞLAT", AppLanguage.RU to "НАЧАТЬ"
        ),
        "web_stop" to mapOf(
            AppLanguage.EN to "STOP", AppLanguage.AR to "إيقاف", AppLanguage.FR to "ARRÊTER",
            AppLanguage.ES to "DETENER", AppLanguage.DE to "STOPP", AppLanguage.TR to "DURDUR", AppLanguage.RU to "СТОП"
        ),
        "web_send_ai" to mapOf(
            AppLanguage.EN to "Send to AI app", AppLanguage.AR to "إرسال لتطبيق ذكاء اصطناعي", AppLanguage.FR to "Envoyer à une IA",
            AppLanguage.ES to "Enviar a app de IA", AppLanguage.DE to "An KI-App senden", AppLanguage.TR to "Yapay zekâ uygulamasına gönder", AppLanguage.RU to "Отправить в ИИ-приложение"
        ),
        "web_share" to mapOf(
            AppLanguage.EN to "Share report", AppLanguage.AR to "مشاركة التقرير", AppLanguage.FR to "Partager",
            AppLanguage.ES to "Compartir", AppLanguage.DE to "Teilen", AppLanguage.TR to "Paylaş", AppLanguage.RU to "Поделиться"
        ),
        "web_export" to mapOf(
            AppLanguage.EN to "Export .md", AppLanguage.AR to "تصدير .md", AppLanguage.FR to "Exporter .md",
            AppLanguage.ES to "Exportar .md", AppLanguage.DE to "Export .md", AppLanguage.TR to ".md dışa aktar", AppLanguage.RU to "Экспорт .md"
        ),
        "findings_title" to mapOf(
            AppLanguage.EN to "Findings", AppLanguage.AR to "النتائج", AppLanguage.FR to "Résultats",
            AppLanguage.ES to "Hallazgos", AppLanguage.DE to "Befunde", AppLanguage.TR to "Bulgular", AppLanguage.RU to "Находки"
        ),
        "findings_empty" to mapOf(
            AppLanguage.EN to "No findings yet. Run a scan from the Website Scanner.",
            AppLanguage.AR to "لا نتائج بعد. شغّل فحصاً من فاحص المواقع.",
            AppLanguage.FR to "Aucun résultat. Lancez un scan.",
            AppLanguage.ES to "Sin hallazgos. Ejecute un escaneo.",
            AppLanguage.DE to "Keine Befunde. Starten Sie einen Scan.",
            AppLanguage.TR to "Bulgu yok. Bir tarama çalıştırın.",
            AppLanguage.RU to "Находок нет. Запустите скан."
        ),
        "score_title" to mapOf(
            AppLanguage.EN to "Security Strength", AppLanguage.AR to "قوة الأمان",
            AppLanguage.FR to "Niveau de sécurité", AppLanguage.ES to "Nivel de seguridad",
            AppLanguage.DE to "Sicherheitsstärke", AppLanguage.TR to "Güvenlik Gücü", AppLanguage.RU to "Уровень безопасности"
        ),
        "score_excellent" to mapOf(
            AppLanguage.EN to "Excellent", AppLanguage.AR to "ممتاز", AppLanguage.FR to "Excellent",
            AppLanguage.ES to "Excelente", AppLanguage.DE to "Ausgezeichnet", AppLanguage.TR to "Mükemmel", AppLanguage.RU to "Отлично"
        ),
        "score_verygood" to mapOf(
            AppLanguage.EN to "Very good", AppLanguage.AR to "جيد جداً", AppLanguage.FR to "Très bon",
            AppLanguage.ES to "Muy bueno", AppLanguage.DE to "Sehr gut", AppLanguage.TR to "Çok iyi", AppLanguage.RU to "Очень хорошо"
        ),
        "score_good" to mapOf(
            AppLanguage.EN to "Good", AppLanguage.AR to "جيد", AppLanguage.FR to "Bon",
            AppLanguage.ES to "Bueno", AppLanguage.DE to "Gut", AppLanguage.TR to "İyi", AppLanguage.RU to "Хорошо"
        ),
        "score_needswork" to mapOf(
            AppLanguage.EN to "Needs work", AppLanguage.AR to "يحتاج تحسين", AppLanguage.FR to "À améliorer",
            AppLanguage.ES to "Mejorable", AppLanguage.DE to "Verbesserungswürdig", AppLanguage.TR to "Geliştirilmeli", AppLanguage.RU to "Требует доработки"
        ),
        "score_atrisk" to mapOf(
            AppLanguage.EN to "At risk", AppLanguage.AR to "خطير", AppLanguage.FR to "À risque",
            AppLanguage.ES to "En riesgo", AppLanguage.DE to "Gefährdet", AppLanguage.TR to "Riskli", AppLanguage.RU to "Под угрозой"
        ),
        "settings_title" to mapOf(
            AppLanguage.EN to "Settings", AppLanguage.AR to "الإعدادات", AppLanguage.FR to "Paramètres",
            AppLanguage.ES to "Ajustes", AppLanguage.DE to "Einstellungen", AppLanguage.TR to "Ayarlar", AppLanguage.RU to "Настройки"
        ),
        "settings_language" to mapOf(
            AppLanguage.EN to "Language", AppLanguage.AR to "اللغة", AppLanguage.FR to "Langue",
            AppLanguage.ES to "Idioma", AppLanguage.DE to "Sprache", AppLanguage.TR to "Dil", AppLanguage.RU to "Язык"
        ),
        "settings_profile" to mapOf(
            AppLanguage.EN to "Resource Profile", AppLanguage.AR to "بروفايل الموارد", AppLanguage.FR to "Profil de ressources",
            AppLanguage.ES to "Perfil de recursos", AppLanguage.DE to "Ressourcenprofil", AppLanguage.TR to "Kaynak profili", AppLanguage.RU to "Профиль ресурсов"
        ),
        "settings_delete" to mapOf(
            AppLanguage.EN to "Delete Scan History & Findings", AppLanguage.AR to "حذف سجل الفحص والنتائج",
            AppLanguage.FR to "Supprimer l'historique", AppLanguage.ES to "Borrar historial", AppLanguage.DE to "Verlauf löschen",
            AppLanguage.TR to "Geçmişi sil", AppLanguage.RU to "Удалить историю"
        ),
        "settings_about" to mapOf(
            AppLanguage.EN to "Cherlogons runs 100% locally. No telemetry, no accounts, no remote backend. For authorized security assessments only.",
            AppLanguage.AR to "يعمل Cherlogons محلياً 100%. لا تتبّع، لا حسابات، لا خادم بعيد. للتقييمات الأمنية المصرّح بها فقط.",
            AppLanguage.FR to "Cherlogons fonctionne 100% en local. Aucune télémétrie. Uniquement pour des tests autorisés.",
            AppLanguage.ES to "Cherlogons funciona 100% local. Sin telemetría. Solo para pruebas autorizadas.",
            AppLanguage.DE to "Cherlogons läuft 100% lokal. Keine Telemetrie. Nur für autorisierte Tests.",
            AppLanguage.TR to "Cherlogons %100 yerel çalışır. Telemetri yok. Yalnızca yetkili testler için.",
            AppLanguage.RU to "Cherlogons работает локально на 100%. Без телеметрии. Только для авторизованного тестирования."
        )
    )
}
