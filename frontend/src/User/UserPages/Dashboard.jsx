import React, { useEffect, useState } from 'react';
import dashboardStyle from './Dashboard.module.css';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import AtChart from './AtChart';
import Swal from 'sweetalert2';

const Dashboard = () => {
    const [isAttendanceActive, setIsAttendanceActive] = useState(localStorage.getItem('isAttendanceActive') === 'true');
    const [duration, setDuration] = useState(0);
    const [username, setUsername] = useState(localStorage.getItem('username'));
    const [loggedIn, setloggedIn] = useState(localStorage.getItem('loggedIn'));
    const [greeting, setGreeting] = useState('');
    const [isButtonDisabled, setButtonDisabled] = useState(false);
    const [email, setEmail] = useState(localStorage.getItem('email'));
    const [message, setMessage] = useState('');

    const navigate = useNavigate();


    // const handleStart = () => {
    //     setIsAttendanceActive(true);
    //     localStorage.setItem('isAttendanceActive', 'true');
    //     axios.post('http://localhost:5000/start');
    //     toast.info('Your Session Started.')

    // };

    // const handleStop = () => {
    //     setIsAttendanceActive(false);
    //     localStorage.setItem('isAttendanceActive', 'false');
    //     console.log('Username:', username);
    //     axios.post('http://localhost:5000/stop', { username })
    //         .then(response => {
    //             const duration = response.data.duration;
    //             console.log('Duration:', duration);
    //             toast.info('Your Session Ended.')
    //             setDuration(duration);
    //         })
    //         .catch(error => console.error('Error:', error));
    // };

    const handleStart = () => {
        Swal.fire({
            title: 'Are you sure?',
            text: "This will start the attendance session!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, start it!'
        }).then((result) => {
            if (result.isConfirmed) {
                setIsAttendanceActive(true);
                localStorage.setItem('isAttendanceActive', 'true');
                axios.post('http://localhost:5000/start');
                toast.info('Your Session Started.')
            }
        });
    };
    
    const handleStop = () => {
        Swal.fire({
            title: 'Are you sure?',
            text: "This will end the attendance session!",
            icon: 'warning',
            showCancelButton: true,
            confirmButtonColor: '#3085d6',
            cancelButtonColor: '#d33',
            confirmButtonText: 'Yes, stop it!'
        }).then((result) => {
            if (result.isConfirmed) {
                setIsAttendanceActive(false);
                localStorage.setItem('isAttendanceActive', 'false');
                console.log('Username:', username);
                axios.post('http://localhost:5000/stop', { username })
                    .then(response => {
                        const duration = response.data.duration;
                        console.log('Duration:', duration);
                        toast.info('Your Session Ended.')
                        setDuration(duration);
                    })
                    .catch(error => console.error('Error:', error));
            }
        });
    };

    useEffect(() => {
        setUsername(localStorage.getItem('username'));
        setEmail(localStorage.getItem('email'));
        const currentHour = new Date().getHours();

        if (currentHour >= 5 && currentHour < 12) {
            setGreeting('Good Morning');
        } else if (currentHour >= 12 && currentHour < 18) {
            setGreeting('Good Afternoon');
        } else if (currentHour >= 18 && currentHour < 23) {
            setGreeting('Good Afternoon');
        } else {
            setGreeting('Good Night');
        }

        console.log('Email:', username);
        axios.post('http://localhost:5000/checkRequest', { email: username })
            .then(response => {
                console.log('Response:', response.data);
                setMessage(response.data);
                setButtonDisabled(response.data.trim() !== '');
            })
            .catch(error => {
                console.error('Error:', error);
            });


        if (loggedIn === 'false') {
            navigate('/login');
            console.log('You are not logged in');
        };
    }, []);

    const handleLeaveRequest = () => {
        const userId = localStorage.getItem('_id');
        const emp_name = localStorage.getItem('username');
        const email = localStorage.getItem('username');

        console.log('User ID:', userId);
        console.log('User Email:', email);

        axios.post('http://localhost:5000/sendLeaveRequest', { emp_name: username, email: email }, { headers: { 'Content-Type': 'application/json' } })
            .then(response => {
                console.log('Leave request sent successfully');
            })
            .catch(error => {
                console.error('Error sending leave request:', error);
            });
    };


    const handleButtonClick = () => {
        setButtonDisabled(true);
    };

    const handleBothClicks = () => {
        handleLeaveRequest();
        handleButtonClick();
    };
    const myStyle = {
        backgroundColor: '#4E31AA',
        color: 'white',
        fontSize: '15px',

    }


    return (
        <>
        <div className='container'>
            <h1 style={{ color: 'var(--dark)' }}>{greeting}, {username}!</h1>
            <div className={`p-sm-5 ${dashboardStyle.time}`}>

                <button className={`btn btn-success ${dashboardStyle.btn}`} onClick={handleStart} disabled={isAttendanceActive}>
                    Start
                </button>

                {duration > 0 && (
                    <h3 className='text-center p-2' style={{ color: 'var(--lighter)' }}>Duration : <br />{duration} minutes</h3>
                )}

                <button className={`btn btn-danger ${dashboardStyle.btn}`} onClick={handleStop} disabled={!isAttendanceActive}>
                    Stop
                </button>

            </div>

            <div className='col-lg-4 col-lg-10 mx-auto mt-5'>
                <div className='d-flex gap-5 mt-5 flex-column' >


                    <div className={`container-fluid border ${dashboardStyle.cont} mx-auto`} style={{ boxShadow: '1px 1px 10px var(--hover)', borderRadius: '10px' }}>

                        <div className='row d-flex align-items-center mx-auto' >

                            <div className='col-lg-4 col-lg-10 mx-auto '>


                                <p style={{ fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold align-items-center d-flex justify-content-center my-auto gap-5' id={dashboardStyle.roww}>Send a request for a Leave
                                    <button className={`btn btn-sm`} style={myStyle} type="button" onClick={handleBothClicks}
                                        disabled={isButtonDisabled}>
                                        {isButtonDisabled ? "Request Sent" : "Confirm"}
                                    </button>
                                </p>

                            </div>

                        </div>
                    </div>

                    <div className={`container-fluid border ${dashboardStyle.cont} mx-auto`} style={{ boxShadow: '1px 1px 10px var(--hover)', borderRadius: '10px' }}>
                        <div className='row d-flex align-items-center mx-auto' >
                            <div className='col-lg-4 col-lg-10 mx-auto '>
                                <p style={{ fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold align-items-center d-flex justify-content-center my-auto gap-5' id={dashboardStyle.message}>{message}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <AtChart />
            </div>

        </>
    );
};

export default Dashboard;
