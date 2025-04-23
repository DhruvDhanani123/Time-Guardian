import React, { useState } from 'react';
import loginStyle from './Login.module.css';
import { Form } from 'react-bootstrap';
import axios from 'axios';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';

const ForgotPassword = () => {
    const [email, setEmail] = useState("");
    const [message, setMessage] = useState('');
    const navigate = useNavigate();

    axios.defaults.withCredentials = true;

    const handleSubmit = (e) => {
        e.preventDefault();

        axios.post('http://localhost:5000/forgot-password', { email })
            .then(result => {
                if (result.data.Status === "Success") {
                    toast.success('Reset link sent to your Email!');
                    navigate('/login');
                }
                else if (result.data.Status === "User not existed") {
                    setMessage('User not existed!!');
                }
            })
            .catch(err => {
                console.log(err);
                toast.error('Error sending reset link');
            });
    };

    return (
        <>
            <div className={`container-fluid ${loginStyle.pacont}`}  >

                <form onSubmit={handleSubmit} className='p-5' style={{ boxShadow: '1px 1px 1000px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
                    <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Forgot Password</p>

                    <Form.Group className="mb-1" controlId="formBasicEmail">
                        <Form.Label className={loginStyle.label}>Email<span className='text-danger'>*</span></Form.Label>
                        <Form.Control
                            className={loginStyle.type}
                            name="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="Enter email"
                            required
                        />
                    </Form.Group>

                    <div >
                        {message && <Form.Text className='text-danger'>{message}</Form.Text>}
                    </div>

                    <button className={`btn mt-4 ${loginStyle.btn}`} type="submit">
                        Send Reset Link
                    </button>

                </form>
            </div>

        </>

    );
}

export default ForgotPassword;
