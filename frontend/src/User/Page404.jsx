import Lottie from 'lottie-react';
import React from 'react';
import errorAnimation from '../Animation/animation_e2.json'

const Page404 = () => {
  return (
    <>
      <div className='container-fluid' style={{background:'#70cfe4'}}>
        <Lottie
          animationData={errorAnimation}
          loop={true}
          autoplay={true}
          speed={1}
          style={{ height: '100vh'}}
        />
      </div>
    </>
  )
}

export default Page404;