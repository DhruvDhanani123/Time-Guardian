import React, { useEffect, useState } from 'react';
import personalStyle from './Personal.module.css';
import { Col, Form } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';


const EmployeeCreate = () => {
    const [formValues, setFormValues] = useState({ fName: "", email: "", mono: "", joinDate: "", salary: "" });
    const [errorMessage, setErrorMessage] = useState(null);

    // const [username, setUsername] = useState(localStorage.getItem('username'));
    const [formErrors, setFormErrors] = useState({});
    const navigate = useNavigate();

    // useEffect(() => {
    //     setUsername(localStorage.getItem('username'));
    // }, []);

    const handleChange = (e) => {
        const { name, value } = e.target;
        
        if (name === "fName") {
            const capitalizedValue = value.replace(/\b\w/g, (c) => c.toUpperCase());
            setFormValues({ ...formValues, [name]: capitalizedValue });
        } else {
            setFormValues({ ...formValues, [name]: value });
        }
    };

    const validate = (values) => {
        const errors = {};
        if (values.mono.length !== 10) {
            errors.mono = "Enter valid mobile no.!";
        }
        return errors;
    };

    const handleSubmit = (e) => {
        e.preventDefault();

        const errors = validate(formValues);
        setFormErrors(errors);

        if (Object.keys(errors).length === 0) {
            axios.post('http://localhost:5000/employeeCreate',formValues)
                .then(result => {
                    console.log(result);
                    navigate('/employee');
                    toast.success('Employee Registration Successful.')
                })
                .catch(err => {
                    console.log(err);
                    setErrorMessage(err.response.data.error);
                }
                );
        }
    };

    return (
        <>
            <div className='container d-flex align-items-center justify-content-center vh-100'>

                <Form className={`p-5 ${personalStyle.frm}`} onSubmit={handleSubmit} style={{ boxShadow: '1px 1px 30px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
                {errorMessage && (
                    <h5 className="text-danger mb-3">
                        {errorMessage}
                    </h5>
                )}
                    <div style={{ color: 'var(--dark)' }} className='h1'>Enter Your Information : </div>
                    <p className='text-danger'>** All fields are compulsory.</p>
                    <div className="mb-3">
                        <Form.Group as={Col} controlId="formGridEmail">
                            <Form.Label className={personalStyle.label}>Full Name<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='fName' value={formValues.fName} onChange={handleChange} className={personalStyle.type} placeholder="Enter full name" required />
                        </Form.Group>
                    </div>

                    <div className="mb-3">
                        <Form.Group as={Col} controlId="formGridEmail">
                            <Form.Label className={personalStyle.label}>E-mail<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='email' value={formValues.email} onChange={handleChange} className={personalStyle.type} placeholder="Enter e-mail" required />
                        </Form.Group>
                    </div>

                    <div className='row' >

                        <div className='col-sm-6'>
                            <Form.Group className=" flex-fill" controlId="formGridAddress1">
                                <Form.Label className={personalStyle.label}>Mobile No.<span className='text-danger'>*</span></Form.Label>
                                <Form.Control type='number' name='mono' value={formValues.mono} onChange={handleChange} className={personalStyle.type} placeholder="Your mobile number" required />
                            </Form.Group>
                            {formErrors.mono &&
                                <Form.Text className="text-danger">
                                    {formErrors.mono}
                                </Form.Text>}
                        </div>

                        <div className='col-sm-6'>
                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                <Form.Label className={personalStyle.label}>Join Date<span className='text-danger'>*</span></Form.Label>
                                <Form.Control type="date" name='joinDate' value={formValues.joinDate} onChange={handleChange} className={personalStyle.type} placeholder="date of joining" required />
                            </Form.Group>
                        </div>

                    </div>

                    <div className='row'>
                        <Form.Group className="mb-3" controlId="formGridAddress1">
                            <Form.Label className={personalStyle.label}>Salary<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='salary' value={formValues.salary} onChange={handleChange} className={personalStyle.type} placeholder="salary" required />
                        </Form.Group>
                    </div>

                    <button className={`btn w-100 ${personalStyle.btn}`} type="submit">
                        Save
                    </button>
                </Form>
            </div >
        </ >
    )
}

export default EmployeeCreate;