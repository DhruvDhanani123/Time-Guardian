import React, { useEffect, useState } from 'react';
import personalStyle from './Personal.module.css';
import { Col, Form } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate, useParams } from 'react-router-dom';
import { toast } from 'react-toastify';

const EmployeeEdit = () => {
    const { id } = useParams();

    const [formValues, setFormValues] = useState({ fName: "", email: "", mono: "", joinDate: "", salary: "" });
    const [formErrors, setFormErrors] = useState({});
    const navigate = useNavigate();

    useEffect(() => {
        axios.get(`http://localhost:5000/getemployee/${id}`)
            .then(result => {
                console.log(result);
                setFormValues(result.data);
            })
            .catch(err => console.log(err))
    }, [id])

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

    // const handleSubmit = async (e) => {
    //     e.preventDefault();

    //     const errors = validate(formValues);
    //     setFormErrors(errors);

    //     if (Object.keys(errors).length === 0) {
    //         await axios.put(`http://localhost:5002/personalEdit/${id}`, formValues)
    //             .then(result => {
    //                 console.log(result);
    //                 // setFormValues(initialValues);
    //                 navigate('/profile');
    //             })
    //             .catch(err => console.log(err));

    //         setIsSubmit(true);
    //     }
    // };

    const handleSubmit = async (e) => {
        e.preventDefault();

        const errors = validate(formValues);
        setFormErrors(errors);

        if (Object.keys(errors).length === 0) {
            await axios.put(`http://localhost:5000/employeeEdit/${id}`, formValues)
                .then(result => {
                    console.log(result);
                    // setFormValues(initialValues);
                    toast.success('Employee Information Updated.')

                    navigate('/employee');
                })
                .catch(err => console.log(err));
        }
    };

    return (
        <>
            <div className='container d-flex align-items-center justify-content-center vh-100'>
                

                <Form className={`p-5 ${personalStyle.frm}`} onSubmit={handleSubmit} style={{ boxShadow: '1px 1px 30px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
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
                                <Form.Control type="date" name='joinDate' value={formValues.joinDate} onChange={handleChange} className={personalStyle.type} placeholder="Your date of birth" required />
                            </Form.Group>
                        </div>

                    </div>

                    <div className='row'>
                        <Form.Group className="mb-3" controlId="formGridAddress1">
                            <Form.Label className={personalStyle.label}>Salary<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='salary' value={formValues.salary} onChange={handleChange} className={personalStyle.type} placeholder="1234 Main St" required />
                        </Form.Group>
                    </div>

                    <button className={`btn w-100 ${personalStyle.btn}`} type="submit">
                        Save
                    </button>
                </Form>
            </div >
        </>
    )
}

export default EmployeeEdit;