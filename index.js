const { Client, GatewayIntentBits, REST, Routes } = require('discord.js');

const TOKEN = '';
const APPLICATION_ID = ''; // من Developer Portal > General Information

const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages
    ] 
});
const express = require('express');
const app = express();
const port = 3000;

let url = "";
let uptimeDate = Date.now();
let requests = 0;
let response = null;

app.use((req, res, next) => {
    const hostname = req.hostname;
    const subdomain = hostname.split('.')[0];
    const domain = hostname.replace(`${subdomain}.`, '');
    
    req.subdomain = subdomain;
    req.domain = domain;

    url = `https://${subdomain}.${domain}/`;
    next();
});

app.get('/', (req, res) => res.send('Hello World!'));

app.listen(port, () => {
    console.log(`Example app listening at ${url}`);
});

// Error handlers
process.on('uncaughtException', (err) => {
    console.error(`Uncaught Exception: ${err.message}`);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Ping interval
setInterval(async () => {
    console.log(url);

    try {
        response = await fetch(url, { method: 'HEAD' });
        requests++;
        console.log(`Request done with status ${response.status} ${requests}`);
    } catch (error) {
        if (error.response) {
            requests++;
            console.log(`Response status: ${error.response.status} ${requests}`);
        } else {
            console.log("Request failed:", error.message);
        }
    } finally {
        response = null;
    }
}, 15000);

const commands = [{
    name: 'ping',
    description: 'أمر بسيط للرد بـ Pong!'
}];

const rest = new REST({ version: '10' }).setToken(TOKEN);

client.once('ready', async () => {
    console.log(`✅ البوت جاهز! تم تسجيل الدخول باسم ${client.user.tag}`);
    
    try {
        await rest.put(
            Routes.applicationCommands(APPLICATION_ID),
            { body: commands }
        );
        console.log('✅ تم تسجيل الأوامر بنجاح!');
    } catch (error) {
        console.error('❌ خطأ في تسجيل الأوامر:', error);
    }
    
    console.log('🎉 يمكنك الحصول على شارة المطور النشط!');
});

client.on('interactionCreate', async interaction => {
    if (!interaction.isChatInputCommand()) return;

    if (interaction.commandName === 'ping') {
        await interaction.reply('🏓 Pong!');
    }
});


client.login(TOKEN);
