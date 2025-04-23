import React, { useState, useEffect } from 'react';
import registerStyle from './Register.module.css';
import { Form } from 'react-bootstrap';
import { NavLink, useNavigate } from 'react-router-dom';
import { VscEye, VscEyeClosed } from 'react-icons/vsc';
import axios from 'axios';
import { toast } from 'react-toastify';
import Lottie from 'lottie-react';
import registerAnimation from '../Animation/animation_register.json';
import logo from '../TIMEBG.png';

const Register = () => {
    const [formValues, setFormValues] = useState({ username: "", email: "", password: "", mono: "" });
    const [formErrors, setFormErrors] = useState({});
    const [isSubmit, setIsSubmit] = useState(false);
    const [passwordType, setPasswordType] = useState("password");
    const navigate = useNavigate();

    const handleChange = (e) => {
        const { name, value } = e.target;
        if (name === "username") {
            const capitalizedValue = value.replace(/\b\w/g, (c) => c.toUpperCase());
            setFormValues({ ...formValues, [name]: capitalizedValue });
        } else {
            setFormValues({ ...formValues, [name]: value });
        }
    };

    const togglePassword = () => {
        if (passwordType === "password") {
            setPasswordType("text")
            return;
        }
        setPasswordType("password")
    }


    // useEffect(() => {
    //     console.log(formErrors);
    //     if (Object.keys(formErrors).length === 0 && isSubmit) {
    //         console.log(formValues);
    //     }
    // }, [formErrors, formValues, isSubmit]);

    const validate = (values) => {
        const errors = {};
        if (!values.username) {
            errors.username = "Name is required!";
        }

        const regex = /^[a-z0-9]+@gmail\.com$/;
        const regexPass = /^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).{8}$/;

        if (!values.email) {
            errors.email = "Email is required!";
        }
        else if (!regex.test(values.email)) {
            errors.email = "This is not a valid email format!";
        }

        if (!values.mono) {
            errors.mono = "Mobile No. is required!";
        }
        else if (values.mono.length !== 10) {
            errors.mono = "Enter valid mobile no.!";
        }

        if (!regexPass.test(values.password)) {
            errors.password = "Password length must be 8 and it must contain minimum one letter only from (A-Z),(a-z),(0-9) !!";
        }
        return errors;
    };

    const handleSubmit = (e) => {
        e.preventDefault();

        const errors = validate(formValues);
        setFormErrors(errors);

        if (Object.keys(errors).length === 0) {
            axios.post('http://localhost:5000/register', formValues)
                .then(result => {
                    console.log(result);
                    navigate('/login')
                    toast.success('Registration successful!');
                })
                .catch(error => {
                    if (error.response && error.response.status === 400) {
                        setFormErrors({ email: 'User with this email already exists !!' });
                    } else {
                        console.error(error);
                    }
                })
                .finally(() => setIsSubmit(true));
        }
    };


    return (
        <>
            <div className={`${registerStyle.pacont}`} >
                <div className={`container border ${registerStyle.cont} mx-auto`} style={{ boxShadow: '1px 1px 100px var(--hover)', borderRadius: '10px' }}>

                    <div className='row d-flex align-items-center' >
                        <div className='col-lg-8 text-center'>
                            <Lottie className={registerStyle.lottie}
                                animationData={registerAnimation}
                                loop={true}
                                autoplay={true}
                                speed={1}
                                style={{ height: '95vh', width: 'auto' }}
                            />

                        </div>

                        <div className='col-lg-4 col-md-10 mx-auto '>
                            <Form className={registerStyle.frm} onSubmit={handleSubmit}>
                                <div className='text-end'>
                                    <img src={logo} alt='' className='text-end' width='auto' height='150px' />
                                </div>

                                <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Register</p>

                                <p className={registerStyle.login}> Already Registered? <NavLink className={registerStyle.link} to="/login">Sign In</NavLink></p>

                                <Form.Group className="mb-3" controlId="formBasicName">
                                    <Form.Label className={registerStyle.label}>Full Name<span className='text-danger'>*</span></Form.Label>
                                    <Form.Control className={registerStyle.type} name="username" placeholder="Enter your name" value={formValues.username} onChange={handleChange} />
                                    {formErrors.username &&
                                        <Form.Text className="text-danger">
                                            {formErrors.username}
                                        </Form.Text>}
                                </Form.Group>


                                <Form.Group className="mb-3" controlId="formBasicEmail">
                                    <Form.Label className={registerStyle.label}>Email<span className='text-danger'>*</span></Form.Label>
                                    <Form.Control className={registerStyle.type} name="email" placeholder="Enter email" value={formValues.email} onChange={handleChange} />
                                    {formErrors.email &&
                                        <Form.Text className="text-danger">
                                            {formErrors.email}
                                        </Form.Text>}
                                </Form.Group>

                                <Form.Group className="mb-3" controlId="formBasicName">
                                    <Form.Label className={registerStyle.label}>Mobile No.<span className='text-danger'>*</span></Form.Label>
                                    <Form.Control className={registerStyle.type} name="mono" placeholder="Enter your mobile no." value={formValues.mono} onChange={handleChange} />
                                    {formErrors.mono &&
                                        <Form.Text className="text-danger">
                                            {formErrors.mono}
                                        </Form.Text>}
                                </Form.Group>

                                <Form.Group className="mb-4" controlId="formBasicPassword">
                                    <Form.Label className={registerStyle.label}>Password<span className='text-danger'>*</span></Form.Label>

                                    <div className='input-group '>
                                        <Form.Control className={registerStyle.type} type={passwordType} name="password" placeholder="Password" value={formValues.password} onChange={handleChange} />

                                        <span onClick={togglePassword} className={`input-group-text input-group-perpend ${registerStyle.type}`} style={{ color: 'var(--white)', background: 'var(--dark)' }}>
                                            {passwordType === "password" ? <span><VscEyeClosed /></span> : <span><VscEye /></span>}
                                        </span>

                                    </div>
                                    {formErrors.password &&
                                        <Form.Text className="text-danger">
                                            {formErrors.password}
                                        </Form.Text>}

                                </Form.Group>

                                <button className={`btn ${registerStyle.btn}`} type="submit">
                                    Create my account
                                </button>
                            </Form>
                        </div>
                    </div>
                </div>
            </div>
        </>
    )
}

export default Register;
