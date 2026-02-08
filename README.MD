Paaswords:

{
"email": "admin@evallo.com",
"password": "admin123"
}

{
"email": "admin@techlabs.com",
"password": "admin123"
}

// routs for teams
app.post("/teams", authenticateToken, async (req, res) => {
try {
const { name, description } = req.body;
const orgId = req.user.orgId;
if (!name) return res.status(400).json({ message: "name required" });
const result = await db.run(
`INSERT INTO teams (organisation_id, name, description) VALUES (?, ?, ?)`,
[orgId, name, description || null],
);
const teamId = result.lastID;
const team = await db.get(`SELECT * FROM teams WHERE id = ?`, [teamId]);
res.status(201).json(team);
} catch (err) {
console.log("Create Team Error:", err);
res.status(500).json({ message: "Server error" });
}
});

app.get("/teams", authenticateToken, async (req, res) => {
try {
const orgId = req.user.orgId;
const teams = await db.all(
`SELECT * FROM teams WHERE organisation_id = ?`,
[orgId],
);
res.json(teams);
} catch (err) {
console.log("Get Teams Error:", err);
res.status(500).json({ message: "Server error" });
}
});
