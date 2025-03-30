import React, { useState } from 'react';
import { NavLink } from "react-router-dom";
import { ShieldCheck, Brain, Layers, Code, Download, KeyRound, Menu, X } from 'lucide-react';
import { motion, AnimatePresence } from "framer-motion";
import CryptoJS from 'crypto-js';
import { useNavigate } from "react-router-dom";
import './Welcome.css';

const modalVariants = {
  initial: { opacity: 0, scale: 0.8 },
  animate: { opacity: 1, scale: 1, transition: { duration: 0.3 } },
  exit: { opacity: 0, scale: 0.8, transition: { duration: 0.2 } }
};

// Feature Item Component - Moved outside of WelcomePage component
const FeatureItem = ({ icon: Icon, title, description }) => (
  <div className="feature-item">
    <Icon className="feature-icon" size={48} />
    <h3 className="feature-title">{title}</h3>
    <p className="feature-description">{description}</p>
  </div>
);

const adminUsers = {
  "robincb21@gmail.com": "00a94d0b71b8d15c31e7fd623d96b84c", // Hash of "robin@123"
  "adwaithashokan08@gmail.com": "dd84b7f5d27f6d3eb04a1d049f6b8305", // Hash of "adwaith@123"
  "mvnavaneeth5@gmail.com": "37c8b01b28b9e7c25bab198cfc4c9c8c", // Hash of "navaneeth@123"
  "ansiyakp25@gmail.com": "d33b99652be5c43ff8e10984ba9504b8" // Hash of "ansiya@123"
};

const WelcomePage = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [click, setClick] = useState(false);
  const [errorMessage, setErrorMessage] = useState('');

  const handleLogin = (e) => {
    e.preventDefault();

    const hashedPassword = CryptoJS.MD5(password).toString();

    if (adminUsers[email] && adminUsers[email] === hashedPassword) {
      localStorage.setItem("authToken", "loggedIn"); // Save login token
      navigate('/dashboard');
    } else {
      setErrorMessage("Invalid email or password.");
    }
  };

  const handleClick = () => {
    setClick(!click); // Toggle menu state
  };

  const scrollToSection = (id) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
    setClick(false); // Close the menu after clicking
  };

  return (
    <div className="welcome-page-container">
      {/* Navbar */}
      <nav className="navbar">
        <div className="nav-container">
          <NavLink exact to="/" className="nav-logo">
            <span>ANOMALYX_</span>
            <span className="icon">
              <Code size={24} />
            </span>
          </NavLink>

          <ul className={click ? "nav-menu active" : "nav-menu"}>
            <li className="nav-item">
              <NavLink exact to="/" className="nav-links" onClick={() => scrollToSection("hero-section")}>
                HOME
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink exact to="#" className="nav-links" onClick={() => scrollToSection("key-features-section")}>
                KEY FEATURES
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink exact to="#" className="nav-links" onClick={() => scrollToSection("about-section")}>
                ABOUT
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink exact to="#" className="nav-links" onClick={() => scrollToSection("contact-section")}>
                CONTACT
              </NavLink>
            </li>
          </ul>

          {/* Hamburger Menu Toggle */}
          <div className="nav-icon" onClick={handleClick}>
            {click ? <X size={24} /> : <Menu size={24} />}
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section id="hero-section" className="hero-section">
        <div className="hero-content">
          <h1 className="hero-title"><span>ANOMALY</span><span>X_</span></h1>
          <p className="hero-subtitle">
            NetGuardian AI ensures real-time threat detection
          </p>
          <button className="get-started-button" onClick={() => setIsModalOpen(true)}>Get Started Now</button>
        </div>
      </section>

      {/* Key Features Section */}
      <section id="key-features-section" className="key-features-section">
        <h2 className="section-title">KEY FEATURES</h2>
        <div className="features-grid">
          <FeatureItem icon={ShieldCheck} title="Proactive Threat Prevention" description="Identify and neutralize threats before they impact your network." />
          <FeatureItem icon={Brain} title="Intelligent Anomaly Detection" description="Leverage advanced AI algorithms to detect unusual network behavior." />
          <FeatureItem icon={Layers} title="Seamless Integration" description="Easily integrate NetGuardian AI into your existing security infrastructure." />
          <FeatureItem icon={Code} title="Customizable Rules and Policies" description="Tailor the system to your specific network environment and security needs." />
          <FeatureItem icon={Download} title="Automated Reporting" description="Generate comprehensive reports to track security performance and compliance." />
          <FeatureItem icon={KeyRound} title="Secure Access Control" description="Ensure only authorized users have access to sensitive network resources." />
        </div>
      </section>

      {/* About Section */}
      <section id="about-section" className="hero-section">
        <h2 className="section-title">ABOUT</h2>
        <div className="hero-content">
          <p className="hero-subtitle">
            AnomalyX is an advanced cybersecurity platform powered by AI, designed to provide real-time threat detection and response.
            Our mission is to safeguard networks by leveraging intelligent anomaly detection and proactive security measures.
          </p>
        </div>
      </section>

      {/* Contact Section */}
      <section id="contact-section" className="hero-section">
        <h2 className="section-title">CONTACT</h2>
        <div className="hero-content">
          <p className="hero-subtitle">
            Have questions or need assistance? Get in touch with our support team at <strong>support@anomalyx.com</strong>.
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <p>© {new Date().getFullYear()} NetGuardian AI. All rights reserved.</p>
      </footer>

      {/* Modal for Login */}
      <AnimatePresence>
        {isModalOpen && (
          <motion.div className="modal-overlay" variants={modalVariants} initial="initial" animate="animate" exit="exit">
            <div className="modal-content">
              <h2 className="modal-title">Login</h2>
              <form onSubmit={handleLogin} className="modal-form">
                <label className="modal-label">Email:</label>
                <input type="email" name="email" value={email} onChange={(e) => setEmail(e.target.value)} className="modal-input" placeholder="your.email@example.com" autoComplete="email" required />
                <label className="modal-label">Password:</label>
                <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="modal-input" placeholder="password" required />
                {errorMessage && <p className="error-message">{errorMessage}</p>}
                <button type="submit" className="modal-button">Login</button>
              </form>
              <button onClick={() => setIsModalOpen(false)} className="close-modal-button">Close</button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default WelcomePage;