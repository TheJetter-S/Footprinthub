import { Routes, Route, Navigate } from 'react-router-dom'
import { useState, useEffect } from 'react'
import Navbar from './components/layout/Navbar'
import HomePage from './pages/HomePage'
import LoginPage from './pages/LoginPage'
import RegisterPage from './pages/RegisterPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import TermsPage from './pages/TermsPage'
import Footer from './components/layout/Footer'

function App() {
  const [token, setToken] = useState<string | null>(
    localStorage.getItem('access_token')
  )
  const [darkMode, setDarkMode] = useState(true)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', darkMode)
  }, [darkMode])

  const handleLogin = (accessToken: string, refreshToken: string) => {
    localStorage.setItem('access_token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)
    setToken(accessToken)
  }

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
    setToken(null)
  }

  return (
    <div className="min-h-screen flex flex-col">
      <Navbar
        isAuthenticated={!!token}
        darkMode={darkMode}
        onToggleTheme={() => setDarkMode(!darkMode)}
        onLogout={handleLogout}
      />
      <main className="flex-1">
        <Routes>
          <Route
            path="/"
            element={
              token ? <HomePage /> : <Navigate to="/login" replace />
            }
          />
          <Route
            path="/login"
            element={
              token ? (
                <Navigate to="/" replace />
              ) : (
                <LoginPage onLogin={handleLogin} />
              )
            }
          />
          <Route
            path="/register"
            element={
              token ? (
                <Navigate to="/" replace />
              ) : (
                <RegisterPage onLogin={handleLogin} />
              )
            }
          />
          <Route
            path="/scan/:scanId"
            element={
              token ? <DashboardPage /> : <Navigate to="/login" replace />
            }
          />
          <Route
            path="/history"
            element={
              token ? <HistoryPage /> : <Navigate to="/login" replace />
            }
          />
          <Route path="/terms" element={<TermsPage />} />
        </Routes>
      </main>
      <Footer />
    </div>
  )
}

export default App
