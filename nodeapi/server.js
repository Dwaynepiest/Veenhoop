const express = require('express');
const db = require('./db'); // Import the database connection
const port = 3000;
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json()); // To parse JSON bodies



app.get('/user', (req, res) => {
    db.query('SELECT * FROM user', (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.post('/user', async (req, res) => {
    const { id, voornaam, tussenvoegsel, achternaam, adres, wachtwoord, email, telefoonnummer, mobiel_nummer } = req.body;

    // Controleer of verplichte velden zijn ingevuld
    if (!voornaam || !achternaam || !email || !wachtwoord) {
        return res.status(400).send('Alle verplichte velden moeten worden ingevuld: voornaam, achternaam, email en wachtwoord');
    }

    try {
        // Hash het wachtwoord
        const hashedPassword = await bcrypt.hash(wachtwoord, 10);

        const query = 'INSERT INTO user (id, voornaam, tussenvoegsel, achternaam, adres, wachtwoord, email, telefoonnummer, mobiel_nummer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)';
        const values = [id, voornaam, tussenvoegsel, achternaam, adres, hashedPassword, email, telefoonnummer, mobiel_nummer];

        db.query(query, values, (err, results) => {
            if (err) {
                console.error('Fout bij het toevoegen van gebruiker:', err);
                return res.status(500).send(err);
            }
            res.status(201).send(`${voornaam} is toegevoegd aan de database`);
        });
    } catch (err) {
        console.error('Fout bij het hashen van het wachtwoord:', err);
        res.status(500).send('Er is een fout opgetreden bij het verwerken van de gegevens');
    }
});

app.post('/login', async (req, res) => {
    const { email, wachtwoord } = req.body;

    // Controleer of verplichte velden zijn ingevuld
    if (!email || !wachtwoord) {
        return res.status(400).send('Email en wachtwoord zijn verplicht');
    }

    try {
        // Haal de gebruiker op uit de database op basis van het emailadres
        const query = 'SELECT * FROM user WHERE email = ?';
        db.query(query, [email], async (err, results) => {
            if (err) {
                console.error('Fout bij het ophalen van gebruiker:', err);
                return res.status(500).send('Er is een fout opgetreden bij het verwerken van de gegevens');
            }

            if (results.length === 0) {
                return res.status(404).send('Gebruiker niet gevonden');
            }

            const user = results[0];

            // Vergelijk het ingevoerde wachtwoord met het gehashte wachtwoord
            const isPasswordValid = await bcrypt.compare(wachtwoord, user.wachtwoord);
            if (!isPasswordValid) {
                return res.status(401).send('Ongeldig wachtwoord');
            }

            // Login succesvol
            res.status(200).send(`Welkom, ${user.voornaam} u bent nu ingelogd!`);
        });
    } catch (err) {
        console.error('Fout bij het verwerken van de login:', err);
        res.status(500).send('Er is een fout opgetreden bij het verwerken van de login');
    }
});

app.put('/user/:id', async (req, res) => {
    const { id } = req.params; // Haal de id uit de URL-parameters
    const { voornaam, tussenvoegsel, achternaam, adres, wachtwoord, email, telefoonnummer, mobiel_nummer } = req.body;

    try {
        // Stap 1: Haal de huidige gegevens van de gebruiker op
        db.query('SELECT * FROM user WHERE id = ?', [id], async (err, results) => {
            if (err) {
                console.error('Fout bij het ophalen van de gebruiker:', err);
                return res.status(500).send('Er is een fout opgetreden bij het ophalen van de gegevens');
            }

            if (results.length === 0) {
                return res.status(404).send(`Gebruiker met id ${id} niet gevonden`);
            }

            const currentData = results[0];

            // Stap 2: Vervang ontbrekende velden door de oude gegevens
            const updatedVoornaam = voornaam || currentData.voornaam;
            const updatedTussenvoegsel = tussenvoegsel || currentData.tussenvoegsel;
            const updatedAchternaam = achternaam || currentData.achternaam;
            const updatedAdres = adres || currentData.adres;
            const updatedEmail = email || currentData.email;
            const updatedTelefoonnummer = telefoonnummer || currentData.telefoonnummer;
            const updatedMobielNummer = mobiel_nummer || currentData.mobiel_nummer;

            // Hash het wachtwoord alleen als een nieuw wachtwoord wordt opgegeven
            const updatedWachtwoord = wachtwoord
                ? await bcrypt.hash(wachtwoord, 10)
                : currentData.wachtwoord;

            // Stap 3: Voer de UPDATE-query uit
            const query = `
                UPDATE user 
                SET 
                    voornaam = ?, 
                    tussenvoegsel = ?, 
                    achternaam = ?, 
                    adres = ?, 
                    wachtwoord = ?, 
                    email = ?, 
                    telefoonnummer = ?, 
                    mobiel_nummer = ? 
                WHERE id = ?`;
            const values = [
                updatedVoornaam,
                updatedTussenvoegsel,
                updatedAchternaam,
                updatedAdres,
                updatedWachtwoord,
                updatedEmail,
                updatedTelefoonnummer,
                updatedMobielNummer,
                id,
            ];

            db.query(query, values, (updateErr, updateResults) => {
                if (updateErr) {
                    console.error('Fout bij het bijwerken van de gebruiker:', updateErr);
                    return res.status(500).send('Er is een fout opgetreden bij het bijwerken van de gegevens');
                }

                res.status(200).send(`Gebruiker met id ${id} is succesvol bijgewerkt`);
            });
        });
    } catch (err) {
        console.error('Fout bij het verwerken van de gegevens:', err);
        res.status(500).send('Er is een fout opgetreden bij het verwerken van de gegevens');
    }
});

app.get('/vakken', (req, res) => {
    db.query('SELECT * FROM vakken', (err, results) => {
        if (err) return res.status(500).send(err);
        res.json(results);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});