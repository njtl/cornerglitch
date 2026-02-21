package i18n

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// LangInfo describes a supported language.
type LangInfo struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Native string `json:"native"`
	RTL    bool   `json:"rtl"`
}

// Handler provides multi-language content generation.
type Handler struct {
	languages    []LangInfo
	langCodes    map[string]bool
	translations map[string]map[string]string // lang -> key -> value
}

// NewHandler creates a new i18n handler with all supported languages loaded.
func NewHandler() *Handler {
	h := &Handler{
		languages: []LangInfo{
			{Code: "en", Name: "English", Native: "English", RTL: false},
			{Code: "es", Name: "Spanish", Native: "Espanol", RTL: false},
			{Code: "fr", Name: "French", Native: "Francais", RTL: false},
			{Code: "de", Name: "German", Native: "Deutsch", RTL: false},
			{Code: "pt", Name: "Portuguese", Native: "Portugues", RTL: false},
			{Code: "ja", Name: "Japanese", Native: "\u65e5\u672c\u8a9e", RTL: false},
			{Code: "zh", Name: "Chinese", Native: "\u4e2d\u6587", RTL: false},
			{Code: "ko", Name: "Korean", Native: "\ud55c\uad6d\uc5b4", RTL: false},
			{Code: "ar", Name: "Arabic", Native: "\u0627\u0644\u0639\u0631\u0628\u064a\u0629", RTL: true},
			{Code: "ru", Name: "Russian", Native: "\u0420\u0443\u0441\u0441\u043a\u0438\u0439", RTL: false},
		},
		langCodes:    make(map[string]bool),
		translations: make(map[string]map[string]string),
	}

	for _, l := range h.languages {
		h.langCodes[l.Code] = true
	}

	h.initTranslations()
	return h
}

// ShouldHandle returns true for language-specific paths and i18n API endpoints.
func (h *Handler) ShouldHandle(path string) bool {
	if path == "/api/i18n/languages" || path == "/api/i18n/translate" {
		return true
	}

	// Check for /{lang}/ or /{lang} paths
	if len(path) >= 3 && path[0] == '/' {
		rest := path[1:]
		var code string
		slashIdx := strings.IndexByte(rest, '/')
		if slashIdx == -1 {
			code = rest
		} else {
			code = rest[:slashIdx]
		}
		if len(code) == 2 && h.langCodes[code] {
			return true
		}
	}

	return false
}

// ServeHTTP dispatches i18n requests and returns the HTTP status code.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) int {
	path := r.URL.Path

	switch path {
	case "/api/i18n/languages":
		return h.serveLanguagesAPI(w, r)
	case "/api/i18n/translate":
		return h.serveTranslateAPI(w, r)
	}

	// Must be a localized content path: /{lang}/...
	lang, subpath := h.parseLangPath(path)
	if lang == "" {
		http.NotFound(w, r)
		return http.StatusNotFound
	}

	return h.serveLocalizedPage(w, r, lang, subpath)
}

// DetectLanguage detects the preferred language from URL path, cookie, or Accept-Language header.
func (h *Handler) DetectLanguage(r *http.Request) string {
	// Priority 1: URL path prefix
	if lang, _ := h.parseLangPath(r.URL.Path); lang != "" {
		return lang
	}

	// Priority 2: Cookie
	if cookie, err := r.Cookie("lang"); err == nil {
		code := cookie.Value
		if h.langCodes[code] {
			return code
		}
	}

	// Priority 3: Accept-Language header
	if al := r.Header.Get("Accept-Language"); al != "" {
		if lang := h.parseAcceptLanguage(al); lang != "" {
			return lang
		}
	}

	// Default
	return "en"
}

// Translate returns the translated string for the given key and language.
func (h *Handler) Translate(key string, lang string) string {
	if t, ok := h.translations[lang]; ok {
		if v, ok := t[key]; ok {
			return v
		}
	}
	// Fallback to English
	if t, ok := h.translations["en"]; ok {
		if v, ok := t[key]; ok {
			return v
		}
	}
	return key
}

// LocalizedSnippet returns HTML <script> + meta tags for language (hreflang, content-language).
func (h *Handler) LocalizedSnippet(lang string) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<meta http-equiv="Content-Language" content="%s">`, lang))
	sb.WriteByte('\n')

	for _, l := range h.languages {
		sb.WriteString(fmt.Sprintf(`<link rel="alternate" hreflang="%s" href="/%s/">`, l.Code, l.Code))
		sb.WriteByte('\n')
	}
	sb.WriteString(`<link rel="alternate" hreflang="x-default" href="/en/">`)
	sb.WriteByte('\n')

	sb.WriteString(`<script>`)
	sb.WriteString(fmt.Sprintf(`document.documentElement.lang="%s";`, lang))
	if h.isRTL(lang) {
		sb.WriteString(`document.documentElement.dir="rtl";`)
	}
	sb.WriteString(`</script>`)
	sb.WriteByte('\n')

	return sb.String()
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func (h *Handler) parseLangPath(path string) (lang string, subpath string) {
	if len(path) < 3 || path[0] != '/' {
		return "", ""
	}
	rest := path[1:]
	slashIdx := strings.IndexByte(rest, '/')
	var code string
	if slashIdx == -1 {
		code = rest
		subpath = "/"
	} else {
		code = rest[:slashIdx]
		subpath = rest[slashIdx:]
		if subpath == "" {
			subpath = "/"
		}
	}
	if len(code) == 2 && h.langCodes[code] {
		return code, subpath
	}
	return "", ""
}

func (h *Handler) isRTL(lang string) bool {
	for _, l := range h.languages {
		if l.Code == lang {
			return l.RTL
		}
	}
	return false
}

type langQuality struct {
	lang string
	q    float64
}

func (h *Handler) parseAcceptLanguage(header string) string {
	parts := strings.Split(header, ",")
	var candidates []langQuality

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		q := 1.0
		langTag := part

		if idx := strings.IndexByte(part, ';'); idx != -1 {
			langTag = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if parsed, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					q = parsed
				}
			}
		}

		// Extract the 2-letter code from tags like "fr-FR"
		code := langTag
		if idx := strings.IndexByte(langTag, '-'); idx != -1 {
			code = langTag[:idx]
		}
		code = strings.ToLower(code)

		if h.langCodes[code] {
			candidates = append(candidates, langQuality{lang: code, q: q})
		}
	}

	if len(candidates) == 0 {
		return ""
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].q > candidates[j].q
	})
	return candidates[0].lang
}

func (h *Handler) serveLanguagesAPI(w http.ResponseWriter, _ *http.Request) int {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(h.languages)
	return http.StatusOK
}

func (h *Handler) serveTranslateAPI(w http.ResponseWriter, r *http.Request) int {
	key := r.URL.Query().Get("key")
	lang := r.URL.Query().Get("lang")

	if key == "" || lang == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "missing required query parameters: key, lang",
		})
		return http.StatusBadRequest
	}

	translation := h.Translate(key, lang)

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"key":         key,
		"lang":        lang,
		"translation": translation,
	})
	return http.StatusOK
}

func (h *Handler) serveLocalizedPage(w http.ResponseWriter, r *http.Request, lang, subpath string) int {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", lang)

	dirAttr := ""
	if h.isRTL(lang) {
		dirAttr = ` dir="rtl"`
	}

	t := func(key string) string {
		return h.Translate(key, lang)
	}

	// Derive page title from the subpath
	pageTitle := t("home")
	pathSegment := ""
	if subpath != "/" {
		pathSegment = strings.Trim(subpath, "/")
		parts := strings.Split(pathSegment, "/")
		last := parts[len(parts)-1]
		last = strings.ReplaceAll(last, "-", " ")
		last = strings.ReplaceAll(last, "_", " ")
		pageTitle = strings.Title(last) //nolint:staticcheck
	}

	// Build breadcrumbs
	var breadcrumbs strings.Builder
	breadcrumbs.WriteString(fmt.Sprintf(`<a href="/%s/">%s</a>`, lang, t("home")))
	if subpath != "/" {
		accumulated := "/" + lang
		segments := strings.Split(strings.Trim(subpath, "/"), "/")
		for _, seg := range segments {
			accumulated += "/" + seg
			label := strings.ReplaceAll(seg, "-", " ")
			label = strings.ReplaceAll(label, "_", " ")
			label = strings.Title(label) //nolint:staticcheck
			breadcrumbs.WriteString(fmt.Sprintf(` &raquo; <a href="%s">%s</a>`, accumulated, label))
		}
	}

	// Build navigation
	navItems := []struct{ key, path string }{
		{"home", ""},
		{"about", "about"},
		{"products", "products"},
		{"services", "services"},
		{"blog", "blog"},
		{"contact", "contact"},
		{"search", "search"},
	}
	var nav strings.Builder
	for _, item := range navItems {
		href := fmt.Sprintf("/%s/%s", lang, item.path)
		if item.path == "" {
			href = fmt.Sprintf("/%s/", lang)
		}
		nav.WriteString(fmt.Sprintf(`        <li><a href="%s">%s</a></li>`+"\n", href, t(item.key)))
	}

	// Build hreflang link tags
	var hreflangLinks strings.Builder
	for _, l := range h.languages {
		altPath := fmt.Sprintf("/%s%s", l.Code, subpath)
		hreflangLinks.WriteString(fmt.Sprintf(`  <link rel="alternate" hreflang="%s" href="%s">`+"\n", l.Code, altPath))
	}
	hreflangLinks.WriteString(fmt.Sprintf(`  <link rel="alternate" hreflang="x-default" href="/en%s">`+"\n", subpath))

	// Build language selector
	var langSelector strings.Builder
	langSelector.WriteString(`      <select onchange="window.location.href=this.value" aria-label="Language">` + "\n")
	for _, l := range h.languages {
		altPath := fmt.Sprintf("/%s%s", l.Code, subpath)
		selected := ""
		if l.Code == lang {
			selected = " selected"
		}
		langSelector.WriteString(fmt.Sprintf(`        <option value="%s"%s>%s (%s)</option>`+"\n", altPath, selected, l.Native, l.Code))
	}
	langSelector.WriteString(`      </select>` + "\n")

	// Build footer links
	footerLinks := []struct{ key, path string }{
		{"privacy_policy", "privacy-policy"},
		{"terms_of_service", "terms-of-service"},
	}
	var footer strings.Builder
	for i, fl := range footerLinks {
		if i > 0 {
			footer.WriteString(" | ")
		}
		footer.WriteString(fmt.Sprintf(`<a href="/%s/%s">%s</a>`, lang, fl.path, t(fl.key)))
	}

	// Build the content body
	var content strings.Builder
	content.WriteString(fmt.Sprintf("    <h2>%s</h2>\n", pageTitle))
	content.WriteString(fmt.Sprintf("    <p>%s. ", t("welcome")))
	content.WriteString("This is a dynamically generated page with localized UI elements. ")
	content.WriteString("The content body is intentionally in English, but all navigation, ")
	content.WriteString("headings, and UI chrome are translated.</p>\n")
	content.WriteString(fmt.Sprintf("    <p><a href=\"/%s/blog\">%s</a></p>\n", lang, t("read_more")))
	content.WriteString("    <section>\n")
	content.WriteString(fmt.Sprintf("      <h3>%s</h3>\n", t("subscribe")))
	content.WriteString("      <form method=\"post\">\n")
	content.WriteString(fmt.Sprintf("        <label>%s: <input type=\"text\" name=\"name\" placeholder=\"%s\"></label><br>\n", t("name"), t("required_field")))
	content.WriteString(fmt.Sprintf("        <label>%s: <input type=\"email\" name=\"email\" placeholder=\"%s\"></label><br>\n", t("email"), t("required_field")))
	content.WriteString(fmt.Sprintf("        <label>%s: <textarea name=\"message\"></textarea></label><br>\n", t("message")))
	content.WriteString(fmt.Sprintf("        <button type=\"submit\">%s</button>\n", t("submit")))
	content.WriteString(fmt.Sprintf("        <button type=\"reset\">%s</button>\n", t("cancel")))
	content.WriteString("      </form>\n")
	content.WriteString("    </section>\n")
	content.WriteString("    <section>\n")
	content.WriteString(fmt.Sprintf("      <p>%s: <a href=\"#\">%s</a> | <a href=\"#\">%s</a> | <a href=\"#\">%s</a></p>\n",
		t("share"), "Twitter", "Facebook", "LinkedIn"))
	content.WriteString(fmt.Sprintf("      <p><a href=\"#\">%s</a> | <a href=\"#\">%s</a></p>\n", t("like"), t("comment")))
	content.WriteString("    </section>\n")
	content.WriteString(fmt.Sprintf("    <p class=\"time-info\">%s &middot; %s &middot; %s</p>\n", t("today"), t("hours_ago"), t("minutes_ago")))

	// Find lang info for the current language
	var currentLang LangInfo
	for _, l := range h.languages {
		if l.Code == lang {
			currentLang = l
			break
		}
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s"%s>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Language" content="%s">
  <title>%s - GlitchServer [%s]</title>
%s  <style>
    body { font-family: sans-serif; margin: 0; padding: 0; }
    header { background: #333; color: #fff; padding: 1rem; }
    header nav ul { list-style: none; padding: 0; display: flex; gap: 1rem; flex-wrap: wrap; }
    header nav a { color: #fff; text-decoration: none; }
    .breadcrumbs { padding: 0.5rem 1rem; background: #f0f0f0; font-size: 0.9em; }
    main { padding: 1rem; max-width: 900px; }
    footer { background: #333; color: #fff; padding: 1rem; margin-top: 2rem; text-align: center; }
    footer a { color: #ccc; }
    .lang-selector { float: right; }
    .time-info { color: #888; font-size: 0.85em; }
    form label { display: block; margin: 0.5rem 0; }
    form button { margin: 0.5rem 0.25rem; padding: 0.4rem 1rem; }
  </style>
</head>
<body>
  <header>
    <div class="lang-selector">
%s    </div>
    <h1>GlitchServer - %s</h1>
    <nav>
      <ul>
%s      </ul>
    </nav>
  </header>
  <div class="breadcrumbs">%s</div>
  <main>
%s  </main>
  <footer>
    <p>%s</p>
    <p>%s &copy; 2024 GlitchServer. %s</p>
  </footer>
</body>
</html>`,
		lang, dirAttr,
		lang,
		pageTitle, currentLang.Native,
		hreflangLinks.String(),
		langSelector.String(),
		currentLang.Native,
		nav.String(),
		breadcrumbs.String(),
		content.String(),
		footer.String(),
		t("copyright"), t("all_rights_reserved"),
	)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(html))
	return http.StatusOK
}

// ---------------------------------------------------------------------------
// Translation data
// ---------------------------------------------------------------------------

func (h *Handler) initTranslations() {
	h.translations["en"] = map[string]string{
		// Navigation
		"home":     "Home",
		"about":    "About",
		"products": "Products",
		"services": "Services",
		"contact":  "Contact",
		"blog":     "Blog",
		"search":   "Search",
		"login":    "Log In",
		"register": "Register",
		"logout":   "Log Out",
		// Actions
		"submit":  "Submit",
		"cancel":  "Cancel",
		"save":    "Save",
		"delete":  "Delete",
		"edit":    "Edit",
		"add":     "Add",
		"remove":  "Remove",
		"update":  "Update",
		"confirm": "Confirm",
		"close":   "Close",
		// Messages
		"welcome":    "Welcome",
		"thank_you":  "Thank you",
		"error":      "Error",
		"not_found":  "Not Found",
		"loading":    "Loading...",
		"success":    "Success",
		"no_results": "No results found",
		// Content
		"read_more":   "Read More",
		"share":       "Share",
		"comment":     "Comment",
		"like":        "Like",
		"follow":      "Follow",
		"subscribe":   "Subscribe",
		"unsubscribe": "Unsubscribe",
		// Forms
		"name":             "Name",
		"email":            "Email",
		"password":         "Password",
		"confirm_password": "Confirm Password",
		"phone":            "Phone",
		"address":          "Address",
		"message":          "Message",
		"required_field":   "Required",
		// Footer
		"privacy_policy":     "Privacy Policy",
		"terms_of_service":   "Terms of Service",
		"copyright":          "Copyright",
		"all_rights_reserved": "All rights reserved",
		// Time
		"today":       "Today",
		"yesterday":   "Yesterday",
		"minutes_ago": "minutes ago",
		"hours_ago":   "hours ago",
		"days_ago":    "days ago",
	}

	h.translations["es"] = map[string]string{
		"home": "Inicio", "about": "Acerca de", "products": "Productos", "services": "Servicios",
		"contact": "Contacto", "blog": "Blog", "search": "Buscar", "login": "Iniciar sesion",
		"register": "Registrarse", "logout": "Cerrar sesion",
		"submit": "Enviar", "cancel": "Cancelar", "save": "Guardar", "delete": "Eliminar",
		"edit": "Editar", "add": "Agregar", "remove": "Quitar", "update": "Actualizar",
		"confirm": "Confirmar", "close": "Cerrar",
		"welcome": "Bienvenido", "thank_you": "Gracias", "error": "Error",
		"not_found": "No encontrado", "loading": "Cargando...", "success": "Exito",
		"no_results": "No se encontraron resultados",
		"read_more": "Leer mas", "share": "Compartir", "comment": "Comentar", "like": "Me gusta",
		"follow": "Seguir", "subscribe": "Suscribirse", "unsubscribe": "Cancelar suscripcion",
		"name": "Nombre", "email": "Correo electronico", "password": "Contrasena",
		"confirm_password": "Confirmar contrasena", "phone": "Telefono", "address": "Direccion",
		"message": "Mensaje", "required_field": "Obligatorio",
		"privacy_policy": "Politica de privacidad", "terms_of_service": "Terminos de servicio",
		"copyright": "Derechos de autor", "all_rights_reserved": "Todos los derechos reservados",
		"today": "Hoy", "yesterday": "Ayer", "minutes_ago": "hace minutos",
		"hours_ago": "hace horas", "days_ago": "hace dias",
	}

	h.translations["fr"] = map[string]string{
		"home": "Accueil", "about": "A propos", "products": "Produits", "services": "Services",
		"contact": "Contact", "blog": "Blog", "search": "Rechercher", "login": "Se connecter",
		"register": "S'inscrire", "logout": "Se deconnecter",
		"submit": "Soumettre", "cancel": "Annuler", "save": "Enregistrer", "delete": "Supprimer",
		"edit": "Modifier", "add": "Ajouter", "remove": "Retirer", "update": "Mettre a jour",
		"confirm": "Confirmer", "close": "Fermer",
		"welcome": "Bienvenue", "thank_you": "Merci", "error": "Erreur",
		"not_found": "Non trouve", "loading": "Chargement...", "success": "Succes",
		"no_results": "Aucun resultat trouve",
		"read_more": "Lire la suite", "share": "Partager", "comment": "Commenter", "like": "Aimer",
		"follow": "Suivre", "subscribe": "S'abonner", "unsubscribe": "Se desabonner",
		"name": "Nom", "email": "Courriel", "password": "Mot de passe",
		"confirm_password": "Confirmer le mot de passe", "phone": "Telephone", "address": "Adresse",
		"message": "Message", "required_field": "Obligatoire",
		"privacy_policy": "Politique de confidentialite", "terms_of_service": "Conditions d'utilisation",
		"copyright": "Droits d'auteur", "all_rights_reserved": "Tous droits reserves",
		"today": "Aujourd'hui", "yesterday": "Hier", "minutes_ago": "il y a quelques minutes",
		"hours_ago": "il y a quelques heures", "days_ago": "il y a quelques jours",
	}

	h.translations["de"] = map[string]string{
		"home": "Startseite", "about": "Uber uns", "products": "Produkte", "services": "Dienstleistungen",
		"contact": "Kontakt", "blog": "Blog", "search": "Suchen", "login": "Anmelden",
		"register": "Registrieren", "logout": "Abmelden",
		"submit": "Absenden", "cancel": "Abbrechen", "save": "Speichern", "delete": "Loschen",
		"edit": "Bearbeiten", "add": "Hinzufugen", "remove": "Entfernen", "update": "Aktualisieren",
		"confirm": "Bestatigen", "close": "Schliessen",
		"welcome": "Willkommen", "thank_you": "Danke", "error": "Fehler",
		"not_found": "Nicht gefunden", "loading": "Laden...", "success": "Erfolg",
		"no_results": "Keine Ergebnisse gefunden",
		"read_more": "Weiterlesen", "share": "Teilen", "comment": "Kommentieren", "like": "Gefallt mir",
		"follow": "Folgen", "subscribe": "Abonnieren", "unsubscribe": "Abbestellen",
		"name": "Name", "email": "E-Mail", "password": "Passwort",
		"confirm_password": "Passwort bestatigen", "phone": "Telefon", "address": "Adresse",
		"message": "Nachricht", "required_field": "Erforderlich",
		"privacy_policy": "Datenschutzrichtlinie", "terms_of_service": "Nutzungsbedingungen",
		"copyright": "Urheberrecht", "all_rights_reserved": "Alle Rechte vorbehalten",
		"today": "Heute", "yesterday": "Gestern", "minutes_ago": "vor Minuten",
		"hours_ago": "vor Stunden", "days_ago": "vor Tagen",
	}

	h.translations["pt"] = map[string]string{
		"home": "Inicio", "about": "Sobre", "products": "Produtos", "services": "Servicos",
		"contact": "Contato", "blog": "Blog", "search": "Buscar", "login": "Entrar",
		"register": "Registrar", "logout": "Sair",
		"submit": "Enviar", "cancel": "Cancelar", "save": "Salvar", "delete": "Excluir",
		"edit": "Editar", "add": "Adicionar", "remove": "Remover", "update": "Atualizar",
		"confirm": "Confirmar", "close": "Fechar",
		"welcome": "Bem-vindo", "thank_you": "Obrigado", "error": "Erro",
		"not_found": "Nao encontrado", "loading": "Carregando...", "success": "Sucesso",
		"no_results": "Nenhum resultado encontrado",
		"read_more": "Leia mais", "share": "Compartilhar", "comment": "Comentar", "like": "Curtir",
		"follow": "Seguir", "subscribe": "Inscrever-se", "unsubscribe": "Cancelar inscricao",
		"name": "Nome", "email": "E-mail", "password": "Senha",
		"confirm_password": "Confirmar senha", "phone": "Telefone", "address": "Endereco",
		"message": "Mensagem", "required_field": "Obrigatorio",
		"privacy_policy": "Politica de Privacidade", "terms_of_service": "Termos de Servico",
		"copyright": "Direitos autorais", "all_rights_reserved": "Todos os direitos reservados",
		"today": "Hoje", "yesterday": "Ontem", "minutes_ago": "minutos atras",
		"hours_ago": "horas atras", "days_ago": "dias atras",
	}

	h.translations["ja"] = map[string]string{
		"home": "\u30db\u30fc\u30e0", "about": "\u6982\u8981", "products": "\u88fd\u54c1", "services": "\u30b5\u30fc\u30d3\u30b9",
		"contact": "\u304a\u554f\u3044\u5408\u308f\u305b", "blog": "\u30d6\u30ed\u30b0", "search": "\u691c\u7d22", "login": "\u30ed\u30b0\u30a4\u30f3",
		"register": "\u767b\u9332", "logout": "\u30ed\u30b0\u30a2\u30a6\u30c8",
		"submit": "\u9001\u4fe1", "cancel": "\u30ad\u30e3\u30f3\u30bb\u30eb", "save": "\u4fdd\u5b58", "delete": "\u524a\u9664",
		"edit": "\u7de8\u96c6", "add": "\u8ffd\u52a0", "remove": "\u9664\u53bb", "update": "\u66f4\u65b0",
		"confirm": "\u78ba\u8a8d", "close": "\u9589\u3058\u308b",
		"welcome": "\u3088\u3046\u3053\u305d", "thank_you": "\u3042\u308a\u304c\u3068\u3046\u3054\u3056\u3044\u307e\u3059", "error": "\u30a8\u30e9\u30fc",
		"not_found": "\u898b\u3064\u304b\u308a\u307e\u305b\u3093", "loading": "\u8aad\u307f\u8fbc\u307f\u4e2d...", "success": "\u6210\u529f",
		"no_results": "\u7d50\u679c\u304c\u898b\u3064\u304b\u308a\u307e\u305b\u3093",
		"read_more": "\u7d9a\u304d\u3092\u8aad\u3080", "share": "\u5171\u6709", "comment": "\u30b3\u30e1\u30f3\u30c8", "like": "\u3044\u3044\u306d",
		"follow": "\u30d5\u30a9\u30ed\u30fc", "subscribe": "\u8cfc\u8aad", "unsubscribe": "\u8cfc\u8aad\u89e3\u9664",
		"name": "\u540d\u524d", "email": "\u30e1\u30fc\u30eb", "password": "\u30d1\u30b9\u30ef\u30fc\u30c9",
		"confirm_password": "\u30d1\u30b9\u30ef\u30fc\u30c9\u78ba\u8a8d", "phone": "\u96fb\u8a71\u756a\u53f7", "address": "\u4f4f\u6240",
		"message": "\u30e1\u30c3\u30bb\u30fc\u30b8", "required_field": "\u5fc5\u9808",
		"privacy_policy": "\u30d7\u30e9\u30a4\u30d0\u30b7\u30fc\u30dd\u30ea\u30b7\u30fc", "terms_of_service": "\u5229\u7528\u898f\u7d04",
		"copyright": "\u8457\u4f5c\u6a29", "all_rights_reserved": "\u5168\u3066\u306e\u6a29\u5229\u3092\u4fdd\u6709",
		"today": "\u4eca\u65e5", "yesterday": "\u6628\u65e5", "minutes_ago": "\u5206\u524d",
		"hours_ago": "\u6642\u9593\u524d", "days_ago": "\u65e5\u524d",
	}

	h.translations["zh"] = map[string]string{
		"home": "\u9996\u9875", "about": "\u5173\u4e8e", "products": "\u4ea7\u54c1", "services": "\u670d\u52a1",
		"contact": "\u8054\u7cfb\u6211\u4eec", "blog": "\u535a\u5ba2", "search": "\u641c\u7d22", "login": "\u767b\u5f55",
		"register": "\u6ce8\u518c", "logout": "\u9000\u51fa",
		"submit": "\u63d0\u4ea4", "cancel": "\u53d6\u6d88", "save": "\u4fdd\u5b58", "delete": "\u5220\u9664",
		"edit": "\u7f16\u8f91", "add": "\u6dfb\u52a0", "remove": "\u79fb\u9664", "update": "\u66f4\u65b0",
		"confirm": "\u786e\u8ba4", "close": "\u5173\u95ed",
		"welcome": "\u6b22\u8fce", "thank_you": "\u8c22\u8c22", "error": "\u9519\u8bef",
		"not_found": "\u672a\u627e\u5230", "loading": "\u52a0\u8f7d\u4e2d...", "success": "\u6210\u529f",
		"no_results": "\u672a\u627e\u5230\u7ed3\u679c",
		"read_more": "\u9605\u8bfb\u66f4\u591a", "share": "\u5206\u4eab", "comment": "\u8bc4\u8bba", "like": "\u559c\u6b22",
		"follow": "\u5173\u6ce8", "subscribe": "\u8ba2\u9605", "unsubscribe": "\u53d6\u6d88\u8ba2\u9605",
		"name": "\u59d3\u540d", "email": "\u7535\u5b50\u90ae\u4ef6", "password": "\u5bc6\u7801",
		"confirm_password": "\u786e\u8ba4\u5bc6\u7801", "phone": "\u7535\u8bdd", "address": "\u5730\u5740",
		"message": "\u6d88\u606f", "required_field": "\u5fc5\u586b",
		"privacy_policy": "\u9690\u79c1\u653f\u7b56", "terms_of_service": "\u670d\u52a1\u6761\u6b3e",
		"copyright": "\u7248\u6743", "all_rights_reserved": "\u4fdd\u7559\u6240\u6709\u6743\u5229",
		"today": "\u4eca\u5929", "yesterday": "\u6628\u5929", "minutes_ago": "\u5206\u949f\u524d",
		"hours_ago": "\u5c0f\u65f6\u524d", "days_ago": "\u5929\u524d",
	}

	h.translations["ko"] = map[string]string{
		"home": "\ud648", "about": "\uc18c\uac1c", "products": "\uc81c\ud488", "services": "\uc11c\ube44\uc2a4",
		"contact": "\uc5f0\ub77d\ucc98", "blog": "\ube14\ub85c\uadf8", "search": "\uac80\uc0c9", "login": "\ub85c\uadf8\uc778",
		"register": "\ud68c\uc6d0\uac00\uc785", "logout": "\ub85c\uadf8\uc544\uc6c3",
		"submit": "\uc81c\ucd9c", "cancel": "\ucde8\uc18c", "save": "\uc800\uc7a5", "delete": "\uc0ad\uc81c",
		"edit": "\ud3b8\uc9d1", "add": "\ucd94\uac00", "remove": "\uc81c\uac70", "update": "\uc5c5\ub370\uc774\ud2b8",
		"confirm": "\ud655\uc778", "close": "\ub2eb\uae30",
		"welcome": "\ud658\uc601\ud569\ub2c8\ub2e4", "thank_you": "\uac10\uc0ac\ud569\ub2c8\ub2e4", "error": "\uc624\ub958",
		"not_found": "\ucc3e\uc744 \uc218 \uc5c6\uc74c", "loading": "\ub85c\ub529 \uc911...", "success": "\uc131\uacf5",
		"no_results": "\uacb0\uacfc\ub97c \ucc3e\uc744 \uc218 \uc5c6\uc2b5\ub2c8\ub2e4",
		"read_more": "\ub354 \uc77d\uae30", "share": "\uacf5\uc720", "comment": "\ub313\uae00", "like": "\uc88b\uc544\uc694",
		"follow": "\ud314\ub85c\uc6b0", "subscribe": "\uad6c\ub3c5", "unsubscribe": "\uad6c\ub3c5 \ucde8\uc18c",
		"name": "\uc774\ub984", "email": "\uc774\uba54\uc77c", "password": "\ube44\ubc00\ubc88\ud638",
		"confirm_password": "\ube44\ubc00\ubc88\ud638 \ud655\uc778", "phone": "\uc804\ud654\ubc88\ud638", "address": "\uc8fc\uc18c",
		"message": "\uba54\uc2dc\uc9c0", "required_field": "\ud544\uc218",
		"privacy_policy": "\uac1c\uc778\uc815\ubcf4\ucc98\ub9ac\ubc29\uce68", "terms_of_service": "\uc774\uc6a9\uc57d\uad00",
		"copyright": "\uc800\uc791\uad8c", "all_rights_reserved": "\ubaa8\ub4e0 \uad8c\ub9ac \ubcf4\uc720",
		"today": "\uc624\ub298", "yesterday": "\uc5b4\uc81c", "minutes_ago": "\ubd84 \uc804",
		"hours_ago": "\uc2dc\uac04 \uc804", "days_ago": "\uc77c \uc804",
	}

	h.translations["ar"] = map[string]string{
		"home": "\u0627\u0644\u0631\u0626\u064a\u0633\u064a\u0629", "about": "\u0645\u0639\u0644\u0648\u0645\u0627\u062a \u0639\u0646\u0627", "products": "\u0627\u0644\u0645\u0646\u062a\u062c\u0627\u062a", "services": "\u0627\u0644\u062e\u062f\u0645\u0627\u062a",
		"contact": "\u0627\u062a\u0635\u0644 \u0628\u0646\u0627", "blog": "\u0627\u0644\u0645\u062f\u0648\u0646\u0629", "search": "\u0628\u062d\u062b", "login": "\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062f\u062e\u0648\u0644",
		"register": "\u0627\u0644\u062a\u0633\u062c\u064a\u0644", "logout": "\u062a\u0633\u062c\u064a\u0644 \u0627\u0644\u062e\u0631\u0648\u062c",
		"submit": "\u0625\u0631\u0633\u0627\u0644", "cancel": "\u0625\u0644\u063a\u0627\u0621", "save": "\u062d\u0641\u0638", "delete": "\u062d\u0630\u0641",
		"edit": "\u062a\u0639\u062f\u064a\u0644", "add": "\u0625\u0636\u0627\u0641\u0629", "remove": "\u0625\u0632\u0627\u0644\u0629", "update": "\u062a\u062d\u062f\u064a\u062b",
		"confirm": "\u062a\u0623\u0643\u064a\u062f", "close": "\u0625\u063a\u0644\u0627\u0642",
		"welcome": "\u0623\u0647\u0644\u0627 \u0648\u0633\u0647\u0644\u0627", "thank_you": "\u0634\u0643\u0631\u0627", "error": "\u062e\u0637\u0623",
		"not_found": "\u063a\u064a\u0631 \u0645\u0648\u062c\u0648\u062f", "loading": "\u062c\u0627\u0631\u064a \u0627\u0644\u062a\u062d\u0645\u064a\u0644...", "success": "\u0646\u062c\u0627\u062d",
		"no_results": "\u0644\u0645 \u064a\u062a\u0645 \u0627\u0644\u0639\u062b\u0648\u0631 \u0639\u0644\u0649 \u0646\u062a\u0627\u0626\u062c",
		"read_more": "\u0627\u0642\u0631\u0623 \u0627\u0644\u0645\u0632\u064a\u062f", "share": "\u0645\u0634\u0627\u0631\u0643\u0629", "comment": "\u062a\u0639\u0644\u064a\u0642", "like": "\u0625\u0639\u062c\u0627\u0628",
		"follow": "\u0645\u062a\u0627\u0628\u0639\u0629", "subscribe": "\u0627\u0634\u062a\u0631\u0627\u0643", "unsubscribe": "\u0625\u0644\u063a\u0627\u0621 \u0627\u0644\u0627\u0634\u062a\u0631\u0627\u0643",
		"name": "\u0627\u0644\u0627\u0633\u0645", "email": "\u0627\u0644\u0628\u0631\u064a\u062f \u0627\u0644\u0625\u0644\u0643\u062a\u0631\u0648\u0646\u064a", "password": "\u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631",
		"confirm_password": "\u062a\u0623\u0643\u064a\u062f \u0643\u0644\u0645\u0629 \u0627\u0644\u0645\u0631\u0648\u0631", "phone": "\u0627\u0644\u0647\u0627\u062a\u0641", "address": "\u0627\u0644\u0639\u0646\u0648\u0627\u0646",
		"message": "\u0631\u0633\u0627\u0644\u0629", "required_field": "\u0645\u0637\u0644\u0648\u0628",
		"privacy_policy": "\u0633\u064a\u0627\u0633\u0629 \u0627\u0644\u062e\u0635\u0648\u0635\u064a\u0629", "terms_of_service": "\u0634\u0631\u0648\u0637 \u0627\u0644\u062e\u062f\u0645\u0629",
		"copyright": "\u062d\u0642\u0648\u0642 \u0627\u0644\u0646\u0634\u0631", "all_rights_reserved": "\u062c\u0645\u064a\u0639 \u0627\u0644\u062d\u0642\u0648\u0642 \u0645\u062d\u0641\u0648\u0638\u0629",
		"today": "\u0627\u0644\u064a\u0648\u0645", "yesterday": "\u0623\u0645\u0633", "minutes_ago": "\u062f\u0642\u0627\u0626\u0642 \u0645\u0636\u062a",
		"hours_ago": "\u0633\u0627\u0639\u0627\u062a \u0645\u0636\u062a", "days_ago": "\u0623\u064a\u0627\u0645 \u0645\u0636\u062a",
	}

	h.translations["ru"] = map[string]string{
		"home": "\u0413\u043b\u0430\u0432\u043d\u0430\u044f", "about": "\u041e \u043d\u0430\u0441", "products": "\u041f\u0440\u043e\u0434\u0443\u043a\u0442\u044b", "services": "\u0423\u0441\u043b\u0443\u0433\u0438",
		"contact": "\u041a\u043e\u043d\u0442\u0430\u043a\u0442\u044b", "blog": "\u0411\u043b\u043e\u0433", "search": "\u041f\u043e\u0438\u0441\u043a", "login": "\u0412\u043e\u0439\u0442\u0438",
		"register": "\u0420\u0435\u0433\u0438\u0441\u0442\u0440\u0430\u0446\u0438\u044f", "logout": "\u0412\u044b\u0439\u0442\u0438",
		"submit": "\u041e\u0442\u043f\u0440\u0430\u0432\u0438\u0442\u044c", "cancel": "\u041e\u0442\u043c\u0435\u043d\u0430", "save": "\u0421\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c", "delete": "\u0423\u0434\u0430\u043b\u0438\u0442\u044c",
		"edit": "\u0420\u0435\u0434\u0430\u043a\u0442\u0438\u0440\u043e\u0432\u0430\u0442\u044c", "add": "\u0414\u043e\u0431\u0430\u0432\u0438\u0442\u044c", "remove": "\u0423\u0431\u0440\u0430\u0442\u044c", "update": "\u041e\u0431\u043d\u043e\u0432\u0438\u0442\u044c",
		"confirm": "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c", "close": "\u0417\u0430\u043a\u0440\u044b\u0442\u044c",
		"welcome": "\u0414\u043e\u0431\u0440\u043e \u043f\u043e\u0436\u0430\u043b\u043e\u0432\u0430\u0442\u044c", "thank_you": "\u0421\u043f\u0430\u0441\u0438\u0431\u043e", "error": "\u041e\u0448\u0438\u0431\u043a\u0430",
		"not_found": "\u041d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u043e", "loading": "\u0417\u0430\u0433\u0440\u0443\u0437\u043a\u0430...", "success": "\u0423\u0441\u043f\u0435\u0445",
		"no_results": "\u0420\u0435\u0437\u0443\u043b\u044c\u0442\u0430\u0442\u044b \u043d\u0435 \u043d\u0430\u0439\u0434\u0435\u043d\u044b",
		"read_more": "\u0427\u0438\u0442\u0430\u0442\u044c \u0434\u0430\u043b\u0435\u0435", "share": "\u041f\u043e\u0434\u0435\u043b\u0438\u0442\u044c\u0441\u044f", "comment": "\u041a\u043e\u043c\u043c\u0435\u043d\u0442\u0430\u0440\u0438\u0439", "like": "\u041d\u0440\u0430\u0432\u0438\u0442\u0441\u044f",
		"follow": "\u041f\u043e\u0434\u043f\u0438\u0441\u0430\u0442\u044c\u0441\u044f", "subscribe": "\u041f\u043e\u0434\u043f\u0438\u0441\u043a\u0430", "unsubscribe": "\u041e\u0442\u043f\u0438\u0441\u0430\u0442\u044c\u0441\u044f",
		"name": "\u0418\u043c\u044f", "email": "\u042d\u043b\u0435\u043a\u0442\u0440\u043e\u043d\u043d\u0430\u044f \u043f\u043e\u0447\u0442\u0430", "password": "\u041f\u0430\u0440\u043e\u043b\u044c",
		"confirm_password": "\u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u043f\u0430\u0440\u043e\u043b\u044c", "phone": "\u0422\u0435\u043b\u0435\u0444\u043e\u043d", "address": "\u0410\u0434\u0440\u0435\u0441",
		"message": "\u0421\u043e\u043e\u0431\u0449\u0435\u043d\u0438\u0435", "required_field": "\u041e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u044c\u043d\u043e",
		"privacy_policy": "\u041f\u043e\u043b\u0438\u0442\u0438\u043a\u0430 \u043a\u043e\u043d\u0444\u0438\u0434\u0435\u043d\u0446\u0438\u0430\u043b\u044c\u043d\u043e\u0441\u0442\u0438", "terms_of_service": "\u0423\u0441\u043b\u043e\u0432\u0438\u044f \u0438\u0441\u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u043d\u0438\u044f",
		"copyright": "\u0410\u0432\u0442\u043e\u0440\u0441\u043a\u043e\u0435 \u043f\u0440\u0430\u0432\u043e", "all_rights_reserved": "\u0412\u0441\u0435 \u043f\u0440\u0430\u0432\u0430 \u0437\u0430\u0449\u0438\u0449\u0435\u043d\u044b",
		"today": "\u0421\u0435\u0433\u043e\u0434\u043d\u044f", "yesterday": "\u0412\u0447\u0435\u0440\u0430", "minutes_ago": "\u043c\u0438\u043d\u0443\u0442 \u043d\u0430\u0437\u0430\u0434",
		"hours_ago": "\u0447\u0430\u0441\u043e\u0432 \u043d\u0430\u0437\u0430\u0434", "days_ago": "\u0434\u043d\u0435\u0439 \u043d\u0430\u0437\u0430\u0434",
	}
}
