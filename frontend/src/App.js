// import logo from './logo.svg';
// import './App.css';
import { useState } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

import Login from './User/Login';
import Page404 from './User/Page404';
import PersonalCreate from './User/UserPages/PersonalCreate';
import PersonalEdit from './User/UserPages/PersonalEdit';
import Register from './User/Register';
import Sidebar from './User/Sidebar';
import Dashboard from './User/UserPages/Dashboard';
import Profile from './User/UserPages/Profile';
import ForgotPassword from './User/ForgotPassword';
import ResetPassword from './User/ResetPassword';

import EmployeeEdit from './Admin/AdminPages/EmployeeEdit';
import EmployeeCreate from './Admin/AdminPages/EmployeeCreate';
import Employee from './Admin/AdminPages/Employee';
import Leave from './Admin/AdminPages/Leave';
import AdminSidebar from './Admin/AdminSidebar';
import UserTaskList from './User/UserTaskList';
import TaskList from './Admin/TaskList';

function App() {

  const [username, setUsername] = useState('');

  const handleLogin = (username) => {
    setUsername(username);
  };

  return (
    <>

      <Routes>
        <Route exact path="/" element={<Navigate to="/login" />} />
        <Route path="/login" element={<Login onLogin={handleLogin} />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset_password/:id/:token" element={<ResetPassword />} />
        <Route path="/personal-edit/:id" element={<PersonalEdit />} />
        <Route path="/personal-create" element={<PersonalCreate />} />

        <Route path="/employee-edit/:id" element={<EmployeeEdit />} />
        <Route path="/employee-create" element={<EmployeeCreate />} />

        <Route path="/*" element={<Page404 />} />

        {/* <Route
          path="/userpage"
          element={
            <Sidebar>
              <UserPage />
            </Sidebar>
          }
        /> */}
        <Route
          path="/dashboard"
          element={
            <Sidebar>
              <Dashboard username={username} />
            </Sidebar>
          }
        />
        <Route
          path="/profile"
          element={
            <Sidebar>
              <Profile />
            </Sidebar>
          }
        />

        <Route
          path="/employee"
          element={
            <AdminSidebar>
              <Employee username={username} />
            </AdminSidebar>
          }
        />
        <Route
          path="/tasks"
          element={
            <AdminSidebar>
              <TaskList />
            </AdminSidebar>
          }
        />
        <Route
          path="/usertasks"
          element={
            <Sidebar>
              <UserTaskList />
            </Sidebar>
          }
        />
        <Route
          path="/leave"
          element={
            <AdminSidebar>
              <Leave />
            </AdminSidebar>
          }
        />
      </Routes>

      <ToastContainer position="top-right"
        autoClose={2000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="dark"
      />

    </>
  );
}

export default App;

// <Route path="/*" element={<Navigate to="/" />} />