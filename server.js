const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const xml2js = require('xml2js');
const url = require('url');
const querystring = require('querystring');

// Конфигурационные пути
const CONFIG = {
    DEVICES_FILE: path.join(__dirname, 'config/devices.json'),
    USERS_FILE: path.join(__dirname, 'config/users.json'),
    LOG_DIR: path.join(__dirname, 'logs'),
    HTML_FILE: path.join(__dirname, 'index.html'),
    PORT: process.env.PORT || 3000
};

// Создаем директорию для логов если не существует
if (!fs.existsSync(CONFIG.LOG_DIR)) {
    fs.mkdirSync(CONFIG.LOG_DIR, { recursive: true });
}

class DigestAuth {
    constructor(username, password) {
        this.username = username;
        this.password = password;
        this.nonceCount = 0;
    }

    parseAuthHeader(header) {
        const params = {};
        if (!header) return params;
        header = header.replace(/^Digest\s+/i, '');
        const regex = /(\w+)=("(?:[^"\\]|\\.)*"|[^, ]+)/g;
        let m;
        while ((m = regex.exec(header)) !== null) {
            let key = m[1];
            let val = m[2];
            if (val.startsWith('"') && val.endsWith('"')) {
                val = val.slice(1, -1);
            }
            params[key] = val;
        }
        return params;
    }

    generateResponse(params, method, uri) {
        const ha1 = crypto.createHash('md5')
            .update(`${this.username}:${params.realm}:${this.password}`)
            .digest('hex');

        const ha2 = crypto.createHash('md5')
            .update(`${method}:${uri}`)
            .digest('hex');

        this.nonceCount++;
        const nc = this.nonceCount.toString().padStart(8, '0');
        const cnonce = crypto.randomBytes(8).toString('hex');

        const response = crypto.createHash('md5')
            .update(`${ha1}:${params.nonce}:${nc}:${cnonce}:auth:${ha2}`)
            .digest('hex');

        const header = [
            `Digest username="${this.username}"`,
            `realm="${params.realm}"`,
            `nonce="${params.nonce}"`,
            `uri="${uri}"`,
            `qop=auth`,
            `nc=${nc}`,
            `cnonce="${cnonce}"`,
            `response="${response}"`
        ].join(', ');

        return header;
    }
}

async function setDoorState(ip, login, password, state, doorNo = 1) {
    let errorCount = 0;
    const messages = [];
    const digestAuth = new DigestAuth(login, password);

    console.log(`🚪 Starting door control for ${ip}`);
    console.log(`🔑 Using login: ${login}`);
    console.log(`🎯 Target state: ${getStateText(state)} (${state})`);

    try {
        const doorParamResult = await sendDoorConfigRequest(ip, digestAuth, state, doorNo);
        if (doorParamResult.success) {
            messages.push('реле установлено');
            console.log('✅ Relay configured successfully');
        } else {
            errorCount++;
            messages.push('error при установке реле');
            console.log('❌ Relay configuration failed');
        }

        const doorControlResult = await sendDoorControlRequest(ip, digestAuth, state, doorNo);
        if (doorControlResult.success) {
            messages.push('статус установлен');
            console.log('✅ Door status set successfully');
        } else {
            errorCount++;
            messages.push('error при установке статуса');
            console.log('❌ Door status setting failed');
        }

        const finalMessage = messages.join(' | ');

        if (errorCount === 0) {
            console.log('🎉 All operations completed successfully!');
        } else {
            console.log(`⚠️ Completed with ${errorCount} error(s)`);
        }

        logToFile(finalMessage, ip, state, doorNo);

        return {
            success: errorCount === 0,
            message: finalMessage,
            errorCount: errorCount
        };

    } catch (error) {
        console.error('💥 Critical error:', error);
        const errorMessage = `Critical error: ${error.message}`;
        logToFile(errorMessage, ip, state, doorNo);
        throw error;
    }
}

async function sendDoorConfigRequest(ip, digestAuth, state, doorNo = 1) {
    let magneticType = 'none';
    if (state === 1 || state === 3) {
        magneticType = 'alwaysClose';
    } else if (state === 2) {
        magneticType = 'alwaysOpen';
    }

    const xmlData = `<DoorParam xmlns="http://www.isapi.org/ver20/XMLSchema" version="2.0">
<doorNo>${doorNo}</doorNo>
<enable>false</enable>
<doorName>Door${doorNo}</doorName>
<openDuration>4</openDuration>
<magneticType>${magneticType}</magneticType>
</DoorParam>`;

    const path = `/ISAPI/AccessControl/Door/param/${doorNo}`;

    try {
        const response = await makeDigestRequest(ip, path, 'PUT', xmlData, digestAuth);
        const parsedXml = await xml2js.parseStringPromise(response, { explicitArray: false });

        if (parsedXml && parsedXml.ResponseStatus && parsedXml.ResponseStatus.statusCode) {
            const statusCode = parseInt(parsedXml.ResponseStatus.statusCode, 10);
            return { success: statusCode === 1, raw: response };
        }

        return { success: true, raw: response };

    } catch (error) {
        console.error('Door config request failed:', error.message);
        return { success: false, error: error.message };
    }
}

async function sendDoorControlRequest(ip, digestAuth, state, doorNo = 1) {
    if (state === 2) {
        return { success: true, skipped: true };
    }
    
    let command = 'resume';
    if (state === 1) command = 'alwaysOpen';
    else if (state === 3) command = 'resume';

    const xmlData = `<RemoteControlDoor><cmd>${command}</cmd></RemoteControlDoor>`;
    const path = `/ISAPI/AccessControl/RemoteControl/door/${doorNo}`;

    try {
        const response = await makeDigestRequest(ip, path, 'PUT', xmlData, digestAuth);
        const parsedXml = await xml2js.parseStringPromise(response, { explicitArray: false });

        if (parsedXml && parsedXml.ResponseStatus && parsedXml.ResponseStatus.statusCode) {
            const statusCode = parseInt(parsedXml.ResponseStatus.statusCode, 10);
            return { success: statusCode === 1, raw: response };
        }

        return { success: true, raw: response };

    } catch (error) {
        console.error('Door control request failed:', error.message);
        return { success: false, error: error.message };
    }
}

function makeDigestRequest(ip, path, method, data, digestAuth) {
    return new Promise((resolve, reject) => {
        console.log(`🌐 Sending ${method} request to: http://${ip}${path}`);

        const firstOptions = {
            hostname: ip,
            port: 80,
            path: path,
            method: method,
            timeout: 10000,
            headers: {
                'Content-Type': 'text/xml',
                'Connection': 'close'
            }
        };

        if (data) {
            firstOptions.headers['Content-Length'] = Buffer.byteLength(data);
        }

        const firstReq = http.request(firstOptions, (firstRes) => {
            let responseData = '';
            firstRes.on('data', chunk => responseData += chunk);
            firstRes.on('end', async () => {
                if (firstRes.statusCode === 401 && firstRes.headers['www-authenticate']) {
                    const authHeaderRaw = firstRes.headers['www-authenticate'];
                    const authParams = digestAuth.parseAuthHeader(authHeaderRaw);

                    const authHeader = digestAuth.generateResponse(authParams, method, path);

                    const secondOptions = {
                        hostname: ip,
                        port: 80,
                        path: path,
                        method: method,
                        timeout: 10000,
                        headers: {
                            'Authorization': authHeader,
                            'Content-Type': 'text/xml',
                            'Connection': 'close'
                        }
                    };
                    if (data) {
                        secondOptions.headers['Content-Length'] = Buffer.byteLength(data);
                    }

                    const secondReq = http.request(secondOptions, (secondRes) => {
                        let body = '';
                        console.log(`📡 Response status: ${secondRes.statusCode}`);
                        secondRes.on('data', chunk => body += chunk);
                        secondRes.on('end', () => {
                            if (secondRes.statusCode >= 200 && secondRes.statusCode < 300) {
                                resolve(body);
                            } else {
                                reject(new Error(`HTTP ${secondRes.statusCode}: ${body}`));
                            }
                        });
                    });

                    secondReq.on('error', reject);
                    secondReq.on('timeout', () => {
                        secondReq.destroy();
                        reject(new Error('Request timeout'));
                    });

                    if (data) secondReq.write(data);
                    secondReq.end();

                } else {
                    if (firstRes.statusCode >= 200 && firstRes.statusCode < 300) {
                        resolve(responseData);
                    } else {
                        reject(new Error(`HTTP ${firstRes.statusCode}: ${responseData}`));
                    }
                }
            });
        });

        firstReq.on('error', reject);
        firstReq.on('timeout', () => {
            firstReq.destroy();
            reject(new Error('Request timeout'));
        });

        if (data) firstReq.write(data);
        firstReq.end();
    });
}

function logToFile(message, ip, state, doorNo = 1) {
    const timestamp = new Date().toISOString();
    const stateText = getStateText(state);
    const logEntry = `[${timestamp}] IP: ${ip}, Door: ${doorNo}, State: ${stateText} (${state}), Message: ${message}\n`;

    const logFileName = `door_control_${new Date().toISOString().split('T')[0]}.log`;
    const logPath = path.join(CONFIG.LOG_DIR, logFileName);

    try {
        fs.appendFileSync(logPath, logEntry, 'utf8');
        console.log(`✅ Log written to: ${logPath}`);
    } catch (error) {
        console.error('❌ Error writing to log file:', error);
    }
}

function getStateText(state) {
    const states = {
        1: 'OPEN',
        2: 'CLOSE',
        3: 'RESUME'
    };
    return states[state] || 'UNKNOWN';
}

function parseCommandLineArgs() {
    const args = process.argv.slice(2);
    const params = {};

    for (let i = 0; i < args.length; i++) {
        if (args[i].startsWith('--')) {
            const key = args[i].slice(2);
            const value = args[i + 1];
            if (value && !value.startsWith('--')) {
                params[key] = value;
                i++;
            } else {
                params[key] = true;
            }
        }
    }

    return params;
}

function validateParams(params) {
    const errors = [];

    if (!params.ip) errors.push('Missing --ip parameter');
    if (!params.login) errors.push('Missing --login parameter');
    if (!params.password) errors.push('Missing --password parameter');
    if (!params.state) errors.push('Missing --state parameter');

    if (params.state && !['1', '2', '3'].includes(params.state)) {
        errors.push('Invalid --state. Use: 1 (open), 2 (close), 3 (resume)');
    }

    return errors;
}

// Функции для работы с устройствами
function loadDevices() {
    try {
        if (!fs.existsSync(CONFIG.DEVICES_FILE)) {
            const defaultDevices = {
                devices: [
                    {
                        name: "Главный вход",
                        ip: "192.168.1.100",
                        login: "admin",
                        password: "admin123",
                        doorNo: 1,
                        lastStatus: 3,
                        lastUpdate: new Date().toISOString()
                    },
                    {
                        name: "Запасной выход",
                        ip: "192.168.1.101",
                        login: "admin",
                        password: "admin123",
                        doorNo: 1,
                        lastStatus: 3,
                        lastUpdate: new Date().toISOString()
                    }
                ]
            };
            saveDevices(defaultDevices);
            console.log('📁 Created default devices file');
            return defaultDevices;
        }
        
        const data = fs.readFileSync(CONFIG.DEVICES_FILE, 'utf8');
        const devices = JSON.parse(data);
        console.log(`📊 Loaded ${devices.devices.length} devices from file`);
        return devices;
    } catch (error) {
        console.error('❌ Error loading devices:', error);
        return { devices: [] };
    }
}

function saveDevices(devicesData) {
    try {
        fs.writeFileSync(CONFIG.DEVICES_FILE, JSON.stringify(devicesData, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Error saving devices:', error);
        return false;
    }
}

// Функции для работы с пользователями
function loadUsers() {
    try {
        if (!fs.existsSync(CONFIG.USERS_FILE)) {
            const defaultUsers = {
                users: [
                    {
                        login: "kalugin66@ya.ru",
                        devices: ["all"], // Специальное значение - доступ ко всем устройствам
                        createdAt: new Date().toISOString()
                    },
                    {
                        login: "blok_a",
                        devices: ["192.168.10.48"], // Доступ только к конкретному устройству
                        createdAt: new Date().toISOString()
                    },
                    {
                        login: "blok_b",
                        devices: ["192.168.10.49"], // Доступ только к конкретному устройству
                        createdAt: new Date().toISOString()
                    }
                ]
            };
            saveUsers(defaultUsers);
            console.log('📁 Created default users file');
            return defaultUsers;
        }
        
        const data = fs.readFileSync(CONFIG.USERS_FILE, 'utf8');
        const users = JSON.parse(data);
        console.log(`👥 Loaded ${users.users.length} users from file`);
        return users;
    } catch (error) {
        console.error('❌ Error loading users:', error);
        return { users: [] };
    }
}

function saveUsers(usersData) {
    try {
        fs.writeFileSync(CONFIG.USERS_FILE, JSON.stringify(usersData, null, 2));
        return true;
    } catch (error) {
        console.error('❌ Error saving users:', error);
        return false;
    }
}

function getUserDevices(userLogin) {
    const usersData = loadUsers();
    const user = usersData.users.find(u => u.login === userLogin);
    
    if (!user) {
        console.log(`❌ User ${userLogin} not found`);
        return [];
    }
    
    if (user.devices.includes("all")) {
        console.log(`✅ User ${userLogin} has access to ALL devices`);
        const allDevices = loadDevices().devices.map(d => d.ip);
        return allDevices;
    }
    
    console.log(`✅ User ${userLogin} has access to devices: ${user.devices.join(', ')}`);
    return user.devices;
}

function validateUserAccess(userLogin, deviceIp) {
    const userDevices = getUserDevices(userLogin);
    return userDevices.includes(deviceIp) || userDevices.includes("all");
}

function updateDeviceStatus(ip, status) {
    const devicesData = loadDevices();
    const device = devicesData.devices.find(d => d.ip === ip);
    
    if (device) {
        device.lastStatus = status;
        device.lastUpdate = new Date().toISOString();
        saveDevices(devicesData);
        console.log(`📝 Updated status for device ${ip} to ${status}`);
        return true;
    }
    return false;
}

function serveHTML(req, res) {
    try {
        if (!fs.existsSync(CONFIG.HTML_FILE)) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('HTML file not found. Please create index.html');
            return;
        }

        const html = fs.readFileSync(CONFIG.HTML_FILE, 'utf8');
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
    } catch (error) {
        console.error('❌ Error serving HTML:', error);
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error loading HTML file');
    }
}

// Веб-сервер
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.query;
    
    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }
    
    // API routes
    if (pathname === '/api/devices' && req.method === 'GET') {
        const userLogin = query.login;
        
        if (!userLogin) {
            res.writeHead(400, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Не указан логин пользователя' }));
            return;
        }
        
        console.log(`🔐 Request from user: ${userLogin}`);
        
        const allDevices = loadDevices().devices;
        const userDevices = getUserDevices(userLogin);
        
        if (userDevices.length === 0) {
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Доступ запрещен или пользователь не найден' }));
            return;
        }
        
        // Фильтруем устройства по доступу пользователя
        let filteredDevices;
        if (userDevices.includes("all")) {
            filteredDevices = allDevices;
        } else {
            filteredDevices = allDevices.filter(device => userDevices.includes(device.ip));
        }
        
        console.log(`📊 Sending ${filteredDevices.length} devices to user ${userLogin}`);
        
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(filteredDevices));
        return;
    }
    
    if (pathname === '/api/control' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', async () => {
            try {
                const { ip, state, login } = JSON.parse(body);
                
                if (!login) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Не указан логин пользователя' }));
                    return;
                }
                
                // Проверяем доступ пользователя к устройству
                if (!validateUserAccess(login, ip)) {
                    res.writeHead(403, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Доступ к устройству запрещен' }));
                    return;
                }
                
                const devicesData = loadDevices();
                const device = devicesData.devices.find(d => d.ip === ip);
                
                if (!device) {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Устройство не найдено' }));
                    return;
                }
                
                console.log(`🎯 Web API: User ${login} setting door state for ${ip} to ${state}`);
                const result = await setDoorState(
                    device.ip, 
                    device.login, 
                    device.password, 
                    parseInt(state), 
                    device.doorNo
                );
                
                if (result.success) {
                    updateDeviceStatus(ip, parseInt(state));
                }
                
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(result));
                
            } catch (error) {
                console.error('❌ API error:', error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: error.message }));
            }
        });
        return;
    }
    
    if (pathname === '/api/users' && req.method === 'GET') {
        // Только для администрирования - в продакшене следует защитить
        const usersData = loadUsers();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(usersData));
        return;
    }
    
    // Serve HTML page
    if (pathname === '/' && req.method === 'GET') {
        serveHTML(req, res);
        return;
    }
    
    // 404 for other routes
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, message: 'Route not found' }));
});

// Запуск сервера
if (require.main === module) {
    const args = parseCommandLineArgs();
    
    // Если есть аргументы командной строки - используем CLI режим
    if (args.ip && args.login && args.password && args.state) {
        const errors = validateParams(args);
        if (errors.length > 0) {
            console.error('❌ Parameter errors:');
            errors.forEach(error => console.error(`   - ${error}`));
            process.exit(1);
        }

        const ip = args.ip;
        const login = args.login;
        const password = args.password;
        const state = parseInt(args.state, 10);
        const doorNo = args.door ? parseInt(args.door, 10) : 1;

        console.log('🚪 Hikvision Door Control Script (CLI Mode)');
        console.log('='.repeat(50));

        setDoorState(ip, login, password, state, doorNo)
            .then(result => {
                console.log('\n' + '='.repeat(50));
                if (result.success) {
                    console.log('✅ Operation completed successfully!');
                } else {
                    console.log(`⚠️ Operation completed with ${result.errorCount} error(s)`);
                }
                console.log(`💬 Message: ${result.message}`);
                process.exit(result.success ? 0 : 1);
            })
            .catch(error => {
                console.error('\n💥 Fatal error:', error.message);
                process.exit(1);
            });
    } else {
        // Запускаем веб-сервер
        server.listen(CONFIG.PORT, () => {
            console.log(`🚪 Hikvision Door Control Service запущен!`);
            console.log(`📍 Веб-интерфейс: http://localhost:${CONFIG.PORT}`);
            console.log(`📊 API устройств: http://localhost:${CONFIG.PORT}/api/devices`);
            console.log(`👥 Файл пользователей: ${CONFIG.USERS_FILE}`);
            console.log(`📁 Файл устройств: ${CONFIG.DEVICES_FILE}`);
            console.log(`📁 HTML файл: ${CONFIG.HTML_FILE}`);
            console.log(`📁 Директория логов: ${CONFIG.LOG_DIR}`);
            console.log('='.repeat(50));
            
            // Загружаем данные при старте
            const devices = loadDevices();
            const users = loadUsers();
            console.log(`📊 Загружено устройств: ${devices.devices.length}`);
            console.log(`👥 Загружено пользователей: ${users.users.length}`);
        });
    }
}

// Функция для периодического обновления статусов
setInterval(() => {
    const devices = loadDevices();
    console.log(`🔄 Проверка статусов устройств (${devices.devices.length} устройств)...`);
}, 15000);

module.exports = { 
    setDoorState, 
    DigestAuth, 
    loadDevices, 
    saveDevices,
    loadUsers,
    saveUsers,
    getUserDevices,
    validateUserAccess,
    server,
    CONFIG
};