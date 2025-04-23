import React, { useState } from 'react';
import {
    FaBars,
    FaUsers,
    FaTasks
} from "react-icons/fa";
import { FiLogOut } from "react-icons/fi";
import { FaCodePullRequest } from "react-icons/fa6";
import { NavLink, useNavigate } from 'react-router-dom';
import sidebarStyle from '../User/Sidebar.module.css';
import axios from 'axios';
import Swal from 'sweetalert2';
import logo from '../TIMESIDEBG.png';

const AdminSidebar = ({ children }) => {

    const navigate = useNavigate();
    const [loggedIn, setloggedIn] = useState(localStorage.getItem('loggedIn'));


    const handleLogout = () => {
        axios.get('http://localhost:5000/logout')
            .then(response => {
                Swal.fire({
                    title: 'Are you sure?',
                    text: "You won't be able to revert this!",
                    icon: 'warning',
                    showCancelButton: true,
                    confirmButtonColor: '#3085d6',
                    cancelButtonColor: '#d33',
                    confirmButtonText: 'Yes, Log out!'
                }).then((result) => {
                    if (result.isConfirmed) {
                        // document.cookie = 'token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                        Swal.fire(
                            'Log out!',
                            'success'
                        )
                        localStorage.clear();
                        localStorage.setItem('loggedIn', false);
                        console.log("loggedIn :" + localStorage.getItem('loggedIn'));
                        navigate('/login');
                    }
                })
            })
            .catch(error => {
                console.error(error);
            });
    };

    const [isOpen, setIsOpen] = useState(false);
    const toggle = () => setIsOpen(!isOpen);
    const menuItem = [
        {
            path: "/employee",
            name: "Employee",
            icon: <FaUsers />
        },
        {
            path: "/tasks",
            name: "Tasks",
            icon: <FaTasks />
        },
        {
            path: "/leave",
            name: "Leave",
            icon: <FaCodePullRequest />
        },
    ]

    return (
        <div className={sidebarStyle.container}>
            <div style={{ width: isOpen ? "250px" : "60px" }} className={sidebarStyle.sidebar}>
                <div className={sidebarStyle.top_section}>
                <h1 style={{ display: isOpen ? "block" : "none" }} className={sidebarStyle.logo}>
                        <img  src={logo} alt='' height='100px'/>
                    </h1>
                    <div style={{ marginLeft: isOpen ? "50px" : "0px" }} className={sidebarStyle.bars}>
                        <FaBars onClick={toggle} />
                    </div>
                </div>
                {
                    menuItem.map((item, index) => (
                        <NavLink to={item.path} key={index} className={sidebarStyle.link}
                            style=
                            {({ isActive }) => {
                                return {
                                    color: isActive ? 'var(--darker)' : '',
                                    background: isActive ? 'var(--white)' : '',
                                    borderRadius: '20px 0px 0px 20px',
                                }
                            }}
                        >
                            <div className={sidebarStyle.icon}>{item.icon}</div>
                            <div style={{ display: isOpen ? "block" : "none" }} className={sidebarStyle.link_text}>{item.name}</div>
                        </NavLink>
                    ))
                }



                <NavLink className={`btn ${sidebarStyle.link}`} onClick={handleLogout}>
                    <div className={`${sidebarStyle.icon}`}><FiLogOut /></div>
                    <div style={{ display: isOpen ? "inline " : "none" }} className={`${sidebarStyle.link_text}`}>
                        Log out
                    </div>
                </NavLink>

            </div>
            <main>{children}</main>
        </div>
    );
};

export default AdminSidebar;