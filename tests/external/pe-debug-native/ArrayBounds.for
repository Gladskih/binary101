      subroutine inspect(a,n)
      integer n
      integer a(-1:3,2:5)
      a(-1,2)=n
      end
      subroutine variable(b,n,m)
      integer n,m
      integer b(-n:n,2:m)
      b(0,2)=n
      end
