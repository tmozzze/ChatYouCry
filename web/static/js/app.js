// web/static/js/app.js

document.addEventListener('DOMContentLoaded', () => {
    const registerForm = document.getElementById('register-form');
    const loginForm = document.getElementById('login-form');
    const createChatForm = document.getElementById('create-chat-form');
    const joinChatForm = document.getElementById('join-chat-form');
    const sendMessageButton = document.getElementById('send-message-button');
    const messageInput = document.getElementById('message');
    const messagesDiv = document.getElementById('messages');
    const logoutButton = document.getElementById('logout-button');
    const deleteChatButton = document.getElementById('delete-chat-btn'); // Новые кнопки
    const fileUploadForm = document.getElementById('file-upload-form');
    const fileInput = document.getElementById('file-input');
    const filesDiv = document.getElementById('files');

    let socket = null;

    // Функция для получения параметра из URL
    function getQueryParam(param) {
        const urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param);
    }

    const roomID = getQueryParam('room_id');

    if (roomID) {
        connectWebSocket(roomID);
    }

        // Функция экранирования HTML (предотвращение XSS)
    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    // Обработка регистрации
    if (registerForm) {
        registerForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(registerForm);
            const response = await fetch('/register', {
                method: 'POST',
                body: formData
            });
            const result = await response.json();
            const messageDiv = document.getElementById('message');
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                if (response.ok) {
                    messageDiv.innerHTML = `<p style="color: green;">${result.message}</p>`;
                    registerForm.reset();
                } else {
                    messageDiv.innerHTML = `<p style="color: red;">${result.error}</p>`;
                }
            }
        });
    }

    // Обработка входа
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loginForm);
            const response = await fetch('/login', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                const messageDiv = document.getElementById('message');
                if (response.ok) {
                    window.location.href = '/messenger';
                } else {
                    messageDiv.innerHTML = `<p style="color: red;">${result.error}</p>`;
                }
            }
        });
    }

    // Обработка создания комнаты
    if (createChatForm) {
        createChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(createChatForm);
            const response = await fetch('/messenger/create_chat', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    alert(`Комната создана с ID: ${result.room_id}`);
                    // Перенаправление на страницу чатов с room_id
                    window.location.href = `/messenger/?room_id=${result.room_id}`;
                } else {
                    alert(`Ошибка: ${result.error}`);
                }
            }
        });
    }

    // Обработка присоединения к комнате
    if (joinChatForm) {
        joinChatForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(joinChatForm);
            const response = await fetch('/messenger/join_chat', {
                method: 'POST',
                body: formData
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    alert(`Присоединились к комнате с ID: ${result.room_id}`);
                    // Перенаправление на страницу чатов с room_id
                    window.location.href = `/messenger/?room_id=${result.room_id}`;
                } else {
                    alert(`Ошибка: ${result.error}`);
                }
            }
        });
    }
    
    function formatTimestamp(timestamp) {
        if (!timestamp) {
            return "Неверный формат времени"; // Возвращаем сообщение об ошибке
        }
    
        const date = new Date(timestamp);
    
        if (isNaN(date.getTime())) { // Проверяем, является ли дата валидной
            return "Неверный формат времени"; // Или верните пустую строку
        }
    
        // Формируем дату в нужном формате
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0'); // Месяцы от 0 до 11
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
    
        // Возвращаем строку в нужном формате
        return `${year}.${month}.${day}, ${hours}:${minutes}:${seconds}`;
    }
    
    
    
    

    // Обработка отправки сообщения через WebSocket
    if (sendMessageButton) {
        sendMessageButton.addEventListener('click', () => {
            const message = messageInput.value.trim();
            if (message && socket && socket.readyState === WebSocket.OPEN) {
                const msg = {
                    type: "chat",
                    content: message,
                    room_id: roomID,
                };
                socket.send(JSON.stringify(msg));
                addMessage(currentUserId, message);
                messageInput.value = '';
            }
        });
    }


    // Обработка выхода из системы
    if (logoutButton) {
        logoutButton.addEventListener('click', async () => {
            const response = await fetch('/logout', {
                method: 'POST'
            });
            if (response.redirected) {
                window.location.href = response.url;
            } else {
                const result = await response.json();
                if (response.ok) {
                    window.location.href = '/';
                } else {
                    alert('Ошибка при выходе из системы');
                }
            }
        });
    }

    // Обработка удаления комнаты
    if (deleteChatButton) {
        deleteChatButton.addEventListener('click', async () => {
            if (confirm('Вы уверены, что хотите удалить эту комнату? Это действие нельзя отменить.')) {
                const roomId = roomID; // roomID уже получен из URL
                if (!roomId) {
                    showNotification('Ошибка', 'Не указан идентификатор комнаты для удаления.', 'danger');
                    return;
                }
                try {
                    const response = await fetch(`/messenger/chat?room_id=${encodeURIComponent(roomId)}`, {
                        method: 'DELETE',
                        headers: {
                            'Content-Type': 'application/json'
                        }
                    });

                    const result = await response.json();
                    if (response.ok) {
                        showNotification('Успех', result.message, 'success');
                        window.location.href = '/messenger/lobby';
                    } else {
                        // Обработка ошибок, возвращаемых сервером
                        showNotification('Ошибка', result.error || 'Неизвестная ошибка', 'danger');
                    }
                } catch (error) {
                    console.error('Ошибка при удалении комнаты:', error);
                    showNotification('Ошибка', 'Произошла ошибка при удалении комнаты.', 'danger');
                }
            }
        });
    }

        // Функция для отображения уведомлений с помощью Bootstrap Toasts
    function showNotification(title, response, type = 'info') {
        const notificationContainer = document.getElementById('notification-container');

        const toastId = `toast-${Date.now()}`;
    
        const toastHTML = `
            <div class="toast" id="${toastId}" role="alert" aria-live="assertive" aria-atomic="true" data-delay="5000">
                <div class="toast-header bg-${type} text-white">
                    <strong class="mr-auto">${title}</strong>
                    <small class="text-muted">только что</small>
                    <button type="button" class="ml-2 mb-1 close" data-dismiss="toast" aria-label="Закрыть">
                        <span aria-hidden="true">&times;</span>
                    </button>
                </div>
               <div class="toast-body">
                    ${response}
                </div>
            </div>
        `;
    
            notificationContainer.insertAdjacentHTML('beforeend', toastHTML);
            const toastElement = document.getElementById(toastId);
            $(toastElement).toast('show');
    
            // Удаляем уведомление из DOM после его скрытия
            toastElement.addEventListener('hidden.bs.toast', function () {
            toastElement.remove();
        });
    }
// Обработка загрузки файла
    if (fileUploadForm) {
        fileUploadForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!fileInput.files[0]) {
                showNotification('Ошибка', 'Файл не выбран', 'danger');
                return;
            }
            const formData = new FormData();
            formData.append('file', fileInput.files[0]);

            console.log(`Отправляем файл в комнату: ${roomID}`);
            try {
                const response = await fetch(`/messenger/chat/send-file?room_id=${encodeURIComponent(roomID)}`, {
                    method: 'POST',
                    body: formData,
                });

                const result = await response.json();
                if (response.ok) {
                    showNotification('Успех', result.message, 'success');
                    fileInput.value = ''; // Сбросить выбор файла
                    fetchFiles(); // Обновить список файлов
                } else {
                    console.error(`Ошибка загрузки файла: ${result.error}`);
                    showNotification('Ошибка', result.error || 'Неизвестная ошибка', 'danger');
                }
            } catch (error) {
                console.error('Ошибка при отправке файла:', error);
                showNotification('Ошибка', 'Ошибка отправки файла', 'danger');
            }
        });
    }   
    async function fetchFiles() {
        try {
            const response = await fetch(`/messenger/chat/files?room_id=${encodeURIComponent(roomID)}`);
            if (response.ok) {
                const files = await response.json();
                const filesDiv = document.getElementById('files');
                filesDiv.innerHTML = ''; // Очистить текущий список
    
                if (files.length === 0) {
                    filesDiv.innerHTML = '<p>Нет файлов в этой комнате.</p>';
                    return;
                }
    
                files.forEach(file => {
                    const fileItem = document.createElement('div');
                    fileItem.className = 'file-item mb-2';
                    fileItem.innerHTML = `
                        <a href="/messenger/chat/download-file?room_id=${encodeURIComponent(roomID)}&file_name=${encodeURIComponent(file.file_name)}" target="_blank">${escapeHtml(file.file_name)}</a>
                        <span class="text-muted" style="font-size: 0.8em;">(${file.file_size} байт)</span>
                    `;
                    filesDiv.appendChild(fileItem);
                });
            } else {
                console.error('Ошибка при получении списка файлов');
            }
        } catch (error) {
            console.error('Ошибка при получении списка файлов:', error);
        }
    }
    
    // Вызов fetchFiles при загрузке страницы или после добавления нового файла
    if (roomID) {
        connectWebSocket(roomID);
        fetchFiles();
    }

    // Функция подключения к WebSocket
    function connectWebSocket(roomID) {
        console.log("ws normalno");
        if (!socket) {
            socket = new WebSocket(`ws://${window.location.host}/messenger/ws?room_id=${roomID}`);

            socket.onopen = function(event) {
                console.log("WebSocket соединение установлено");
            };

            socket.onmessage = function(event) {
                try {
                    const data = JSON.parse(event.data); // Разбираем JSON
                    console.log("Получено сообщение через WebSocket:", data);
    
                    // Проверяем, что данные содержат корректные поля
                    if (data && data.type === "chat") {
                        const { sender, content, timestamp } = data; // Извлекаем отправителя, текст сообщения и время
                        if (sender && content && timestamp) {
                            addMessage(sender, content, timestamp); // Добавляем сообщение в интерфейс
                        } else {
                            console.warn("Получено некорректное сообщение:", data);
                        }
                    } else if (data.type === "chat_deleted") {
                        showNotification('Чат удалён', 'Комната, в которой вы находитесь, была удалена.', 'warning');
                        window.location.href = '/messenger/lobby';
                    } else {
                        console.warn("Неизвестный тип сообщения:", data.type);
                    }
                } catch (err) {
                    console.error("Ошибка при разборе сообщения WebSocket:", err);
                }
            };
        }
        

        socket.onclose = function(event) {
            console.log("WebSocket соединение закрыто");
        };

        socket.onerror = function(error) {
            console.error("WebSocket ошибка:", error);
        };
    }
    function addMessage(senderId, message) {
        const messagesContainer = document.getElementById('messages');
        const messageElement = document.createElement('div');
        const isCurrentUser = senderId === currentUserId; // Убедитесь, что currentUserId определен
        // Добавляем класс в зависимости от отправителя
        const formattedTimestamp = formatTimestamp(new Date().toISOString()); // Форматируем время

        messageElement.classList.add('message', isCurrentUser ? 'current-user' : 'other-user');
    
        // Создаем HTML-структуру сообщения
        messageElement.innerHTML = `
            <strong>${isCurrentUser ? 'Вы' : senderId}:</strong> 
            <span style="word-wrap: break-word; overflow-wrap: break-word; white-space: pre-wrap;">${escapeHtml(message)}</span> 
            <div>
                <span class="text-muted" style="font-size: 0.8em;">${formattedTimestamp}</span>
            </div>
        `;
    
        // Добавляем сообщение в контейнер
        messagesContainer.appendChild(messageElement);
    
        // Прокручиваем контейнер вниз
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }
    function notifyUserJoined(roomID) {
        const message = JSON.stringify({ type: "user_joined", roomID });
        socket.send(message);
    }
    
});