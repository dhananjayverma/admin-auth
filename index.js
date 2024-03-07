require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();
const PORT = 5000;



app.use(bodyParser.json());


mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error.message);
        process.exit(1); // Exit the process if there's an error connecting to MongoDB
    });

// Define the managementInfo schema
const userManagementInfoSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    countryCode: String,
    phoneNumber: String,
});

// Define the user schema
const userSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String,
    societyName: String,
    countryCode: String,
    phoneNumber: String,
    city: String,
    country: String,
    profileImage: String,
    managementInfo: [userManagementInfoSchema],
    role: { type: String, enum: ['user', 'admin'], default: 'user' }, // Add a role field
    isAdminVerified: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);







// Middleware for decoding JWT and setting req.user
const authenticateJWT = async (req, res, next) => {
    const token = req.header('Authorization')?.split(" ")[1];



    if (!token) {
        return res.status(401).json({ error: 'Unauthorized - No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized - Invalid token' });
    }
};

const authorizeAdmin = async (req, res, next) => {
    const requestingUserId = req.user.userId;

    try {
        const user = await User.findById(requestingUserId);

        if (!user) {
            return res.status(403).json({ error: 'Permission denied. User not found.' });
        }

        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Permission denied. Only admin users can perform this action.' });
        }

        next(); // Continue to the next middleware or route handler
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};








// Signup route
app.post('/signup', async (req, res) => {
    try {
        const {
            firstName,
            lastName,
            email,
            password,
            societyName,
            countryCode,
            phoneNumber,
            city,
            country,
            profileImage,
            managementInfo,
        } = req.body;

        // Hash the password before saving it to the database
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create an array of managementInfo objects
        const managementInfoArray = managementInfo.map(info => ({
            firstName: info.firstName,
            lastName: info.lastName,
            countryCode: info.countryCode,
            phoneNumber: info.phoneNumber,
        }));

        const newUser = new User({
            firstName,
            lastName,
            email,
            password: hashedPassword,
            societyName,
            countryCode,
            phoneNumber,
            city,
            country,
            profileImage,
            managementInfo: managementInfoArray,
        });

        await newUser.save();

        res.status(201).json({ message: 'User created successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});




// Login route
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Check if the user is an user
        if (user.role === 'user') {
            // Additional checks for admin verification
            if (!user.isAdminVerified) {
                return res.status(401).json({ error: 'User not verified by admin' });
            }
            // Admin login logic, if needed
        }

        // Create a JWT token for authentication
        const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});



// User verification route with PATCH method
app.patch('/verify-user/:userId', authenticateJWT, authorizeAdmin, async (req, res) => {
    try {
        const { userId } = req.params;

        // Check if the requesting user is an admin (you may want to implement proper authentication for admins)
        const requestingUser = await User.findById(req.user.userId);

        if (!requestingUser || requestingUser.role !== 'admin') {
            return res.status(403).json({ error: 'Permission denied. Only admin users can verify users.' });
        }

        // Find the user to be verified by their ID
        const userToVerify = await User.findById(userId);

        if (!userToVerify) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update the user's isAdminVerified field to true
        userToVerify.isAdminVerified = true;
        await userToVerify.save();

        res.json({ message: 'User verified by admin' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


// Get all users route
app.get('/get-all-users', authenticateJWT, authorizeAdmin, async (req, res) => {
    try {
        const allUsers = await User.find();
        res.json(allUsers);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});




app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
