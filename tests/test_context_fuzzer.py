from scanner.context_fuzzer import (
    detect_reflection_context,
    generate_contextual_payloads,
)


def test_detect_reflection_html_body():
    """Detecta reflejo en el cuerpo HTML fuera de etiquetas."""
    html = "<html><body><h1>Resultados para: testProbe123</h1></body></html>"
    contexts = detect_reflection_context(html, "testProbe123")
    assert contexts == ["HTML_BODY"]

    payloads = generate_contextual_payloads(contexts)
    assert any("<script>" in p for p in payloads)


def test_detect_reflection_attribute_value():
    """Detecta reflejo dentro de un atributo HTML estándar."""
    html = '<div><input type="text" name="search" value="testProbe123"></div>'
    contexts = detect_reflection_context(html, "testProbe123")
    assert contexts == ["ATTR_VALUE"]

    payloads = generate_contextual_payloads(contexts)
    assert any('"' in p and "onfocus" in p for p in payloads)


def test_detect_reflection_uri_attribute():
    """Detecta reflejo dentro de un atributo URI como href o src."""
    html = '<p>Visita nuestro enlace: <a href="testProbe123">Click</a></p>'
    contexts = detect_reflection_context(html, "testProbe123")
    assert contexts == ["URI_ATTR"]

    payloads = generate_contextual_payloads(contexts)
    assert any("javascript:" in p for p in payloads)


def test_detect_reflection_script_block():
    """Detecta reflejo dentro de un bloque JavaScript."""
    html = "<script>var userQuery = 'testProbe123'; console.log(userQuery);</script>"
    contexts = detect_reflection_context(html, "testProbe123")
    assert contexts == ["SCRIPT_BLOCK"]

    payloads = generate_contextual_payloads(contexts)
    assert any("';" in p or "alert(1)" in p for p in payloads)


def test_detect_reflection_html_comment():
    """Detecta reflejo dentro de un comentario HTML."""
    html = "<!-- Debug query: testProbe123 --> <div>Contenido</div>"
    contexts = detect_reflection_context(html, "testProbe123")
    assert contexts == ["HTML_COMMENT"]

    payloads = generate_contextual_payloads(contexts)
    assert any("-->" in p for p in payloads)


def test_multiple_reflection_contexts_detected():
    """Detecta múltiples contextos si el parámetro se refleja en varios lugares."""
    html = """
    <!-- Consulta: testProbe123 -->
    <input name="q" value="testProbe123">
    <script>var q = "testProbe123";</script>
    """
    contexts = detect_reflection_context(html, "testProbe123")
    assert "HTML_COMMENT" in contexts
    assert "ATTR_VALUE" in contexts
    assert "SCRIPT_BLOCK" in contexts

    payloads = generate_contextual_payloads(contexts)
    # Debe incluir payloads de ruptura para los distintos contextos
    assert any("-->" in p for p in payloads)
    assert any("onfocus" in p for p in payloads)
    assert any("alert" in p for p in payloads)
