import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import loginStyle from './Login.module.css';
import { Form } from 'react-bootstrap';
import { VscEye, VscEyeClosed } from 'react-icons/vsc';
import axios from 'axios';
import { toast } from 'react-toastify';
import Lottie from 'lottie-react';
import loginAnimation from '../Animation/animation_login.json';
import logo from '../TIMEBG.png';


const Login = ({ onLogin }) => {

    const [formValues, setFormValues] = useState({ email: "", password: "" });
    const [formErrors, setFormErrors] = useState({});
    const [isSubmit, setIsSubmit] = useState(false);
    const [passwordType, setPasswordType] = useState("password");
    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormValues({ ...formValues, [name]: value });
    };

    const handleLogin = () => {
        onLogin(formValues.email);
        localStorage.setItem('username', formValues.email);
        console.log(formValues.email);
    };


    // useEffect(() => {
    //     console.log(formErrors);
    //     if (Object.keys(formErrors).length === 0 && isSubmit) {
    //         console.log(formValues);
    //     }
    // }, [formErrors, formValues, isSubmit]);

    const togglePassword = () => {
        if (passwordType === "password") {
            setPasswordType("text")
            return;
        }
        setPasswordType("password")
    }

    const validate = (values) => {
        const errors = {};
        if (!values.email.trim()) {
            errors.email = "Email is required!";
        }
        if (!values.password.trim()) {
            errors.password = "Password is required!";
        }
        return errors;
    };

    axios.defaults.withCredentials = true;

    const handleSubmit = (e) => {
        e.preventDefault();

        const errors = validate(formValues);
        setFormErrors(errors);

        if (Object.keys(errors).length === 0) {
            axios.post('http://localhost:5000/login', formValues)
                .then(res => {
                    if (res.status === 200) {
                        const token = res.data.token;
                        const dashboard = res.data.dashboard;

                        localStorage.setItem('token', token);
                        localStorage.setItem('dashboard', dashboard);

                        navigate(dashboard === 'adminDashboard' ? '/employee' : '/dashboard');

                        console.log("token :" + token);
                        localStorage.setItem('loggedIn', true);
                        console.log("loggedIn :" + localStorage.getItem('loggedIn'));
                        toast.success('Login successful!');
                    }
                })
                .catch(err => {
                    console.error(err);
                    if (err.response && err.response.data && err.response.data.message) {
                        setFormErrors({ serverError: err.response.data.message });
                    } else {
                        setFormErrors({ serverError: "An error occurred !!" });
                    }
                });
        }
    };


    // const handleSubmit = (e) => {
    //     e.preventDefault();

    //     const errors = validate(formValues);
    //     setFormErrors(errors);

    //     if (Object.keys(errors).length === 0) {
    //         axios.post('http://localhost:5000/login', formValues)
    //             .then(res => {
    //                 if (res.status === 200) {
    //                     navigate('/dashboard');
    //                     toast.success('Login successful!');
    //                 }
    //             })
    //             .catch(err => {
    //                 console.error(err);
    //                 if (err.response && err.response.data && err.response.data.message) {
    //                     setFormErrors({ ...formErrors, serverError: err.response.data.message });
    //                 } else {
    //                     setFormErrors({ ...formErrors, serverError: "An error occurred !!" });
    //                 }
    //             });

    //         setIsSubmit(true);
    //     }
    // };

    return (
        <>
            <div className={loginStyle.pacont}>
                <div className={`container  mx-auto`} style={{ boxShadow: '1px 1px 100px var(--hover)', borderRadius: '10px' }}>
                    <div className="row d-flex align-items-center" >

                        <div className="col-lg-8 text-center">
                            <Lottie className={loginStyle.lottie}
                                animationData={loginAnimation}
                                loop={true}
                                autoplay={true}
                                speed={1}
                                style={{ height: '95vh', width: 'auto' }}
                            />

                        </div>

                        <div className={`col-lg-4 col-md-10 mx-auto`}>
                            <div className={loginStyle.frm}>
                                <div className='text-end'>
                                    <img src={logo} alt='' className='text-end' width='auto' height='150px' />
                                </div>
                                <form onSubmit={handleSubmit}>
                                    <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Sign in
                                    </p>

                                    <div className='mb-2'>
                                        {formErrors.serverError &&
                                            <Form.Text className="text-danger">
                                                {formErrors.serverError}
                                            </Form.Text>
                                        }
                                    </div>

                                    <Form.Group className="mb-4" controlId="formBasicEmail">
                                        <Form.Label className={loginStyle.label}>Email<span className='text-danger'>*</span></Form.Label>
                                        <Form.Control
                                            className={loginStyle.type}
                                            value={formValues.email}
                                            name="email"
                                            onChange={handleChange}
                                            placeholder="Enter email"

                                        />
                                        {formErrors.email &&
                                            <Form.Text className="text-danger">
                                                {formErrors.email}
                                            </Form.Text>}
                                    </Form.Group>

                                    <Form.Group className="mb-4" controlId="formBasicPassword">

                                        <Form.Label className={loginStyle.label}>Password<span className='text-danger'>*</span></Form.Label>

                                        <div className='input-group '>
                                            <Form.Control
                                                className={loginStyle.type}
                                                type={passwordType}
                                                onChange={handleChange}
                                                value={formValues.password}
                                                name="password"
                                                placeholder="Password"

                                            />
                                            <span onClick={togglePassword} className={`input-group-text input-group-perpend ${loginStyle.type}`} style={{ color: 'var(--white)', background: 'var(--dark)' }}>
                                                {passwordType === "password" ? <span><VscEyeClosed /></span> : <span><VscEye /></span>}
                                            </span>
                                        </div>
                                        {formErrors.password &&
                                            <Form.Text className="text-danger">
                                                {formErrors.password}
                                            </Form.Text>}
                                    </Form.Group>

                                    <p className={loginStyle.fogPass}><NavLink to="/forgot-password" className={loginStyle.link}>
                                        Forgot password?
                                    </NavLink></p>

                                    <button className={`btn ${loginStyle.btn}`} onClick={handleLogin} type="submit">
                                        Login
                                    </button>

                                    <p className={loginStyle.register}> Not yet registered? <NavLink className={loginStyle.link} to="/register"> Sign up</NavLink></p>
                                </form>
                            </div>
                        </div>
                    </div>
                </div >
            </div>
        </>

    )
}

export default Login;

