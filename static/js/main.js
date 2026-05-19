/**
 * main.js - Logica del Frontend para DiamondEye Threat Intelligence Dashboard
 * ============================================================================
 *
 * Flujo de comunicacion:
 *
 *   1. El usuario selecciona un archivo .txt y hace clic en "Escanear".
 *   2. main.js intercepta el submit (preventDefault).
 *   3. Valida que haya un archivo .txt seleccionado.
 *   4. Construye un FormData con el archivo.
 *   5. Envia POST a /api/escanear mediante fetch().
 *   6. El backend responde con { "task_id": "uuid" }.
 *   7. main.js inicia un POLLING cada 2s a GET /api/estado/<task_id>.
 *   8. En cada respuesta, actualiza la barra de progreso (% y texto).
 *   9. Cuando status === "done":
 *      a. Oculta la barra de progreso.
 *      b. Muestra el contenedor de resultados.
 *      c. Dibuja grafica de pastel con Chart.js (Limpias vs Maliciosas).
 *      d. Llena la tabla HTML con los resultados (colores condicionales).
 *  10. Si status === "error": muestra el mensaje de error.
 */

document.addEventListener("DOMContentLoaded", () => {

    // ---- Cache de referencias DOM ----
    const form = document.getElementById("scan-form");
    const fileInput = document.getElementById("file-input");
    const fileNameSpan = document.getElementById("file-name");
    const fileLabel = document.getElementById("file-label");
    const scanBtn = document.getElementById("scan-btn");
    const uploadError = document.getElementById("upload-error");
    const globalError = document.getElementById("global-error");

    const progressContainer = document.getElementById("progress-container");
    const progressFill = document.getElementById("progress-fill");
    const progressText = document.getElementById("progress-text");
    const progressPercent = document.getElementById("progress-percent");

    const resultsContainer = document.getElementById("results-container");
    const summaryTotal = document.getElementById("summary-total");
    const summaryClean = document.getElementById("summary-clean");
    const summaryMalicious = document.getElementById("summary-malicious");
    const summaryBogons = document.getElementById("summary-bogons");
    const summaryErrors = document.getElementById("summary-errors");
    const resultsBody = document.getElementById("results-body");
    const chartCanvas = document.getElementById("results-chart");

    let chartInstance = null;  // Referencia a la grafica de Chart.js
    let pollInterval = null;   // Referencia al intervalo de polling

    // ---- Utilidad: mostrar/ocultar elementos ----
    function hide(el) { el.classList.add("hidden"); }
    function show(el) { el.classList.remove("hidden"); }

    // ---- Utilidad: mostrar error ----
    function showError(message, target = globalError) {
        target.textContent = message;
        show(target);
    }

    function clearError(target = globalError) {
        target.textContent = "";
        hide(target);
    }

    // ---- Actualizar nombre del archivo seleccionado ----
    fileInput.addEventListener("change", () => {
        if (fileInput.files.length > 0) {
            fileNameSpan.textContent = fileInput.files[0].name;
        } else {
            fileNameSpan.textContent = "Ningun archivo seleccionado";
        }
    });

    // ---- Interceptar submit del formulario ----
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        clearError(uploadError);
        clearError(globalError);

        // Validar que se haya seleccionado un archivo
        if (fileInput.files.length === 0) {
            showError("Selecciona un archivo .txt antes de escanear.", uploadError);
            return;
        }

        const file = fileInput.files[0];

        // Validar extension .txt
        if (!file.name.toLowerCase().endsWith(".txt")) {
            showError("Solo se permiten archivos con extension .txt", uploadError);
            return;
        }

        // Deshabilitar boton y ocultar resultados previos
        scanBtn.disabled = true;
        scanBtn.textContent = "Enviando...";
        hide(resultsContainer);
        hide(uploadError);
        hide(globalError);

        // Construir FormData con el archivo
        const formData = new FormData();
        formData.append("file", file);

        try {
            // ---- Paso 1: POST a /api/escanear para obtener task_id ----
            const response = await fetch("/api/escanear", {
                method: "POST",
                body: formData,
            });

            if (!response.ok) {
                const errData = await response.json().catch(() => null);
                throw new Error(
                    errData?.error || `Error del servidor (HTTP ${response.status})`
                );
            }

            const { task_id } = await response.json();

            // ---- Paso 2: Mostrar barra de progreso e iniciar polling ----
            show(progressContainer);
            progressFill.style.width = "0%";
            progressPercent.textContent = "0%";
            progressText.textContent = "Iniciando escaneo...";
            scanBtn.textContent = "Escaneando...";

            // Iniciar polling cada 2 segundos
            pollInterval = setInterval(() => pollStatus(task_id), 2000);

        } catch (err) {
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <span class="btn-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                         stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                </span>
                Escanear
            `;
            showError(err.message, globalError);
            hide(progressContainer);
        }
    });

    // ---- Polling: consultar estado del escaneo ----
    async function pollStatus(taskId) {
        try {
            const response = await fetch(`/api/estado/${taskId}`);

            if (!response.ok) {
                const errData = await response.json().catch(() => null);
                throw new Error(
                    errData?.error || `Error al consultar estado (HTTP ${response.status})`
                );
            }

            const data = await response.json();

            if (data.status === "running") {
                // Actualizar barra de progreso
                const progress = data.progress || 0;
                const total = data.total || 1;  // evitar division por cero
                const percent = Math.round((progress / total) * 100);

                progressFill.style.width = `${percent}%`;
                progressPercent.textContent = `${percent}%`;
                progressText.textContent = `Escaneando IP ${progress} de ${total}...`;
            }

            if (data.status === "done") {
                // Escaneo completado exitosamente
                stopPolling();
                scanBtn.disabled = false;
                scanBtn.innerHTML = `
                    <span class="btn-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                             stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                    </span>
                    Escanear
                `;

                // Completar barra al 100%
                progressFill.style.width = "100%";
                progressPercent.textContent = "100%";
                progressText.textContent = "Escaneo completado!";

                // Ocultar progreso y mostrar resultados
                setTimeout(() => {
                    hide(progressContainer);
                    show(resultsContainer);
                    renderResults(data.metadata, data.results);
                }, 600);
            }

            if (data.status === "error") {
                // Error durante el escaneo
                stopPolling();
                scanBtn.disabled = false;
                scanBtn.innerHTML = `
                    <span class="btn-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                             stroke="currentColor" stroke-width="2">
                            <circle cx="11" cy="11" r="8"/>
                            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                        </svg>
                    </span>
                    Escanear
                `;
                hide(progressContainer);
                showError(data.error || "Error desconocido durante el escaneo.", globalError);
            }

        } catch (err) {
            stopPolling();
            scanBtn.disabled = false;
            scanBtn.innerHTML = `
                <span class="btn-icon">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
                         stroke="currentColor" stroke-width="2">
                        <circle cx="11" cy="11" r="8"/>
                        <line x1="21" y1="21" x2="16.65" y2="16.65"/>
                    </svg>
                </span>
                Escanear
            `;
            hide(progressContainer);
            showError(err.message, globalError);
        }
    }

    // ---- Detener polling ----
    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    // ---- Renderizar resultados: grafica + tabla ----
    function renderResults(metadata, results) {
        // 1. Actualizar tarjetas de resumen
        summaryTotal.textContent = metadata.total;
        summaryClean.textContent = metadata.clean;
        summaryMalicious.textContent = metadata.malicious;
        summaryBogons.textContent = metadata.bogons;
        summaryErrors.textContent = metadata.errors;

        // 2. Dibujar grafica de pastel con Chart.js
        renderChart(metadata.clean, metadata.malicious);

        // 3. Poblar la tabla HTML
        populateTable(results);
    }

    // ---- Grafica de pastel (Chart.js) ----
    function renderChart(cleanCount, maliciousCount) {
        // Destruir grafica anterior si existe
        if (chartInstance) {
            chartInstance.destroy();
            chartInstance = null;
        }

        const ctx = chartCanvas.getContext("2d");

        chartInstance = new Chart(ctx, {
            type: "pie",
            data: {
                labels: [
                    `Limpias (${cleanCount})`,
                    `Maliciosas (${maliciousCount})`,
                ],
                datasets: [{
                    data: [cleanCount, maliciousCount],
                    backgroundColor: [
                        "#00ffcc",   // Verde neon para limpias
                        "#ff3355",   // Rojo alerta para maliciosas
                    ],
                    borderColor: [
                        "rgba(0, 255, 204, 0.3)",
                        "rgba(255, 51, 85, 0.3)",
                    ],
                    borderWidth: 2,
                    hoverOffset: 12,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#c8d6e5",
                            font: {
                                size: 13,
                                weight: "600",
                            },
                            padding: 16,
                            usePointStyle: true,
                            pointStyle: "circle",
                        },
                    },
                    tooltip: {
                        backgroundColor: "rgba(10, 14, 23, 0.95)",
                        titleColor: "#e0eaf0",
                        bodyColor: "#c8d6e5",
                        borderColor: "rgba(0, 255, 204, 0.2)",
                        borderWidth: 1,
                        padding: 12,
                        cornerRadius: 8,
                        callbacks: {
                            label: function (context) {
                                const total = cleanCount + maliciousCount;
                                const pct = total > 0
                                    ? ((context.raw / total) * 100).toFixed(1)
                                    : "0.0";
                                return `${context.label}: ${context.raw} (${pct}%)`;
                            },
                        },
                    },
                },
            },
        });
    }

    // ---- Tabla de resultados con colores condicionales ----
    function populateTable(results) {
        resultsBody.innerHTML = "";

        if (!results || results.length === 0) {
            const row = document.createElement("tr");
            row.innerHTML = `<td colspan="4" style="text-align:center; color:#6c8aa0; padding:2rem;">
                No hay resultados para mostrar.
            </td>`;
            resultsBody.appendChild(row);
            return;
        }

        // Mapa de etiquetas de estado en espanol
        const statusLabels = {
            "clean": "Limpia",
            "malicious": "Maliciosa",
            "bogon": "Bogon",
            "error": "Error",
        };

        results.forEach((r) => {
            const tr = document.createElement("tr");
            const statusClass = `status-${r.status}`;
            const label = statusLabels[r.status] || r.status;
            const count = r.status === "malicious" ? r.malicious_count : "—";

            tr.innerHTML = `
                <td><code>${escapeHtml(r.ip)}</code></td>
                <td class="${statusClass}">${label}</td>
                <td>${count}</td>
                <td>${escapeHtml(r.date)}</td>
            `;

            resultsBody.appendChild(tr);
        });
    }

    // ---- Utilidad: escape HTML basico para prevenir XSS ----
    function escapeHtml(text) {
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

});
