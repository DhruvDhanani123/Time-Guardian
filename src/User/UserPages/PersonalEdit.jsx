import React, { useState, useEffect } from 'react';
import personalStyle from './Personal.module.css';
import { Form, Col, Tab, Tabs } from 'react-bootstrap';
import axios from 'axios';
import { useNavigate, useParams } from 'react-router-dom';
import { toast } from 'react-toastify';

const PersonalEdit = () => {
    const { id } = useParams();
    const [key, setKey] = useState('home');

    const initialValues = { fName: "", bDate: "", mono: "", address: "", city: "", state: "" };
    const [formValues, setFormValues] = useState(initialValues);
    const [formErrors, setFormErrors] = useState({});
    const [isSubmit, setIsSubmit] = useState(false);
    const navigate = useNavigate();

    useEffect(() => {
        axios.get(`http://localhost:5000/getUser/${id}`)
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
        // if (!values.fName) {
        //   errors.fName = "Name is required!";
        // }
        // if (!values.mono) {
        //   errors.mono = "Mobile No. is required!";
        // }
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
            await axios.put(`http://localhost:5000/personalEdit/${id}`, formValues) // Changed from post to put
                .then(result => {
                    console.log(result);
                    // setFormValues(initialValues);
                    toast.success('Information Updated.')

                    navigate('/profile');
                })
                .catch(err => console.log(err));

            setIsSubmit(true);
        }
    };



    return (
        <>
            <div className='container d-flex align-items-center justify-content-center vh-100'>
                {/* <div className='row' eventKey="home" title="Edit Personal Details">
                    <div className="col mx-auto"> */}

                <Form className={`p-5 ${personalStyle.frm}`} onSubmit={handleSubmit} style={{ boxShadow: '1px 1px 30px var(--hover)', background: 'var(--lighter)', borderRadius: '10px' }}>
                    <div style={{ color: 'var(--dark)' }} className='h1'>Edit Your Information : </div>
                    <p className='text-danger'>** All fields are compulsory.</p>
                    <div className="mb-3">
                        <Form.Group as={Col} controlId="formGridEmail">
                            <Form.Label className={personalStyle.label}>Full Name<span className='text-danger'>*</span></Form.Label>
                            <Form.Control type='text' name='fName' value={formValues.fName} onChange={handleChange} className={personalStyle.type} placeholder="Enter your full name" required />
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

export default PersonalEdit;
