import React, { useEffect, useState } from 'react';
import personalStyle from './Personal.module.css';
import { Form, Col, Tab, Tabs } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate, useParams } from 'react-router-dom';
import { toast } from 'react-toastify';

const PersonalCreate = () => {
    const [key, setKey] = useState('home');

    const [formValues, setFormValues] = useState({ fName: "", bDate: "", mono: "", address: "", city: "", state: "" });
    const [username, setUsername] = useState(localStorage.getItem('username'));
    const [formErrors, setFormErrors] = useState({});
    const [isSubmit, setIsSubmit] = useState(false);
    const [errorMessage, setErrorMessage] = useState(null);
    const navigate = useNavigate();

    useEffect(() => {
        setUsername(localStorage.getItem('username'));
    }, []);

    const handleChange = (e) => {
        const { name, value } = e.target;
        setFormValues({ ...formValues, [name]: value.replace(/\b\w/g, (c) => c.toUpperCase()) });
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
            const dataToSend = {
                ...formValues,
                username: username
            };
            axios.post('http://localhost:5000/personalCreate', dataToSend)
                .then(result => {
                    console.log(result);
                    navigate('/profile');
                    toast.success('Information Registration Successful.')

                })
                .catch(err => {
                    console.log(err);
                    setErrorMessage(err.response.data.error);
                }
                );
            setIsSubmit(true);
        }
    };

    // useEffect(() => {
    //     console.log(formErrors);
    //     if (Object.keys(formErrors).length === 0 && isSubmit) {
    //         console.log(formValues);
    //     }
    // }, [formErrors]);

    return (
        <>
            <div className='container d-flex align-items-center justify-content-center vh-100'>
                {/* <div className='row' eventKey="home" title="Edit Personal Details">
                    <div className="col mx-auto"> */}
                
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
                            <Form.Control type='text' name='fName' value={formValues.fName} onChange={handleChange} className={personalStyle.type} placeholder="Enter your full name" required/>
                            {formErrors.fName &&
                                <Form.Text className="text-danger">
                                    {formErrors.fName}
                                </Form.Text>}
                        </Form.Group>
                    </div>

                    <div className='row' >

                        <div className='col-sm-6'>
                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                <Form.Label className={personalStyle.label}>Birth Date<span className='text-danger'>*</span></Form.Label>
                                <Form.Control type="date" name='bDate' value={formValues.bDate} onChange={handleChange} className={personalStyle.type} placeholder="Your date of birth" required />
                            </Form.Group>
                        </div>

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

                    </div>

                    <div className='row'>
                        <Form.Group className="mb-3" controlId="formGridAddress1">
                            <Form.Label className={personalStyle.label}>Address<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='address' value={formValues.address} onChange={handleChange} className={personalStyle.type} placeholder="1234 Main St" required />
                        </Form.Group>
                    </div>

                    <div className='row'>

                        <div className='col-sm-6'>
                            <Form.Group className="mb-3 flex-fill " controlId="formGridAddress1">
                                <Form.Label className={personalStyle.label}>City<span className='text-danger'>*</span></Form.Label>
                                <Form.Control type='text' name='city' value={formValues.city} onChange={handleChange} className={personalStyle.type} placeholder="Your city" required />
                            </Form.Group>
                        </div>

                        <div className='col-sm-6'>
                            <Form.Group className="mb-5 flex-fill " controlId="formGridAddress1">
                                <Form.Label className={personalStyle.label}>State<span className='text-danger'>*</span></Form.Label>
                                <Form.Control type='text' name='state' value={formValues.state} onChange={handleChange} className={personalStyle.type} placeholder="Your state" required />
                            </Form.Group>
                        </div>
                    </div>
                    <div>
                        <button className={`btn w-100 ${personalStyle.btn}`} type="submit">
                            Save
                        </button>
                    </div>
                </Form>
            </div>
            {/* </div>
            </div> */}
        </>
    )
}

export default PersonalCreate;
