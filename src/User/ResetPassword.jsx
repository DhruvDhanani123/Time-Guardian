import React, { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import { Form } from 'react-bootstrap';
import loginStyle from './Login.module.css';
import { toast } from 'react-toastify';

const ResetPassword = () => {
    const [password, setPassword] = useState("");
    const [formErrors, setFormErrors] = useState({});
    const [isSubmit, setIsSubmit] = useState(false);
    const navigate = useNavigate();
    const { id, token } = useParams();

    const validate = (values) => {
        const errors = {};
        const regexPass = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8}$/;

        if (!regexPass.test(values)) {
            errors.password = "Password length must be 8 and It must contain minimum one letter only from (A-Z),(a-z),(0-9) !";
        }
        return errors;
    };

    axios.defaults.withCredentials = true;

    const handleSubmit = (e) => {
        e.preventDefault();

        const errors = validate(password);
        setFormErrors(errors);

        if (Object.keys(errors).length === 0) {

            axios.post(`http://localhost:5000/reset-password/${id}/${token}`, { password })
                .then(res => {
                    if (res.status === 200) {
                        navigate('/login');
                        toast.success("Password reset successfully.")  // Redirect to login page after successful password reset
                    }
                })
                .catch(err => {
                    if (err.response && err.response.data && err.response.data.message) {
                        setFormErrors({ ...formErrors, serverError: err.response.data.message });
                    } else {
                        setFormErrors({ ...formErrors, serverError: "An error occurred" });
                    }
                })
                .finally(() => setIsSubmit(true));
        }
    }

    return (
        <>
            <div className={`container-fluid ${loginStyle.pacont}`}  >

                <form onSubmit={handleSubmit} className='p-5' style={{ boxShadow: '1px 1px 1000px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' , width:'400px'}}>

                    <p style={{ fontSize: "30px", fontWeight: "900", color: "var(--dark)" }} className='font-weight-bold'>Reset Password</p>

                    <div className='mb-2'>
                        {formErrors.serverError &&
                            <Form.Text className="text-danger">
                                {formErrors.serverError}    
                            </Form.Text>
                        }
                    </div>

                    <Form.Group className="mb-4" controlId="formBasicEmail">
                        <Form.Label className={loginStyle.label}>New password<span className='text-danger'>*</span></Form.Label>
                        <Form.Control
                            className={loginStyle.type}
                            type="text"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter your new password"
                            required
                        />
                        {formErrors.password &&
                            <Form.Text className="text-danger">
                                {formErrors.password}
                            </Form.Text>}
                    </Form.Group>

                    <button className={`btn ${loginStyle.btn}`} type="submit">
                        Submit
                    </button>

                </form>
            </div>
        </>
    );
}

export default ResetPassword;
